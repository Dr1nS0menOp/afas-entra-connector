// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The afas-entra-sync Authors
//! Notifications end to end: a failing sync, silence while nothing changes, recovery;
//! points of attention in plain language; email through Graph, Teams, Slack and a signed
//! webhook; personal data only where allowed; check-logs.

mod common;

use afas_entra_sync::config::Config;
use afas_entra_sync::error::exit;
use afas_entra_sync::modules::webhook::{hex, hmac_sha256};
use afas_entra_sync::sync::{RunOptions, RunResult, check_logs, run};
use chrono::Days;
use common::*;
use mockito::{Matcher, Mock, Server, ServerGuard};
use serde_json::{Map, Value, json};
use std::sync::{Arc, Mutex};
use tracing_subscriber::prelude::*;

const HOOK_SECRET: &str = "0123456789abcdef-notify";
const MAIL_APP: &str = "c0000000-0000-0000-0000-00000000000e";

type Seen = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

struct Env {
    afas: ServerGuard,
    ms: ServerGuard,
    hook: ServerGuard,
    dir: tempfile::TempDir,
    seen: Seen,
}

fn today() -> chrono::NaiveDate {
    today_ams()
}
fn minus(n: u64) -> chrono::NaiveDate {
    today().checked_sub_days(Days::new(n)).unwrap()
}

impl Env {
    fn new() -> Self {
        let mut e = Env {
            afas: Server::new(),
            ms: Server::new(),
            hook: Server::new(),
            dir: tempfile::tempdir().unwrap(),
            seen: Arc::default(),
        };
        e.ms.mock("POST", format!("/{TENANT}/oauth2/v2.0/token").as_str())
            .with_body(r#"{"access_token":"tok","expires_in":3600}"#)
            .create();
        for (name, path) in [
            ("teams", "/teams"),
            ("slack", "/slack"),
            ("itsm", "/notify"),
        ] {
            write_secret(
                &e.dir.path().join(format!("{name}.url")),
                format!("{}{path}", e.hook.url()).as_bytes(),
            );
        }
        write_secret(&e.dir.path().join("hook.secret"), HOOK_SECRET.as_bytes());
        e
    }

    fn rows(&mut self, rows: &[Map<String, Value>]) {
        self.afas.reset();
        self.afas
            .mock("GET", "/ProfitRestServices/connectors/Entra_Medewerkers")
            .match_query(Matcher::Any)
            .with_body(afas_body(rows))
            .create();
    }

    fn afas_down(&mut self) {
        self.afas.reset();
        self.afas
            .mock("GET", "/ProfitRestServices/connectors/Entra_Medewerkers")
            .match_query(Matcher::Any)
            .with_status(503)
            .with_body("maintenance")
            .create();
    }

    fn upload_ok(&mut self) {
        self.ms
            .mock(
                "POST",
                format!("/v1.0/servicePrincipals/{SP}/synchronization/jobs/{JOB}/bulkUpload")
                    .as_str(),
            )
            .with_status(202)
            .create();
    }

    /// Records every message a channel receives (by path).
    fn catch(&mut self, server: &str, method: &str, path: Matcher) -> Mock {
        let seen = self.seen.clone();
        let s = match server {
            "ms" => &mut self.ms,
            _ => &mut self.hook,
        };
        s.mock(method, path)
            .with_status(202)
            .with_body_from_request(move |req| {
                seen.lock()
                    .unwrap()
                    .push((req.path().to_string(), req.body().unwrap().clone()));
                if let Some(sig) = req.header("x-afasentrasync-signature").first() {
                    let ts = req.header("x-afasentrasync-timestamp")[0]
                        .to_str()
                        .unwrap()
                        .to_string();
                    let mut signed = ts.into_bytes();
                    signed.push(b'.');
                    signed.extend_from_slice(req.body().unwrap());
                    assert_eq!(
                        sig.to_str().unwrap(),
                        format!(
                            "sha256={}",
                            hex(&hmac_sha256(HOOK_SECRET.as_bytes(), &signed))
                        )
                    );
                }
                Vec::new()
            })
            .create()
    }

    fn catch_all(&mut self) {
        self.catch(
            "hook",
            "POST",
            Matcher::Regex("^/(teams|slack|notify)$".into()),
        );
        self.catch("ms", "POST", Matcher::Regex("sendMail$".into()));
    }

    fn take(&self) -> Vec<(String, Value)> {
        std::mem::take(&mut *self.seen.lock().unwrap())
            .into_iter()
            .map(|(p, b)| (p, serde_json::from_slice(&b).unwrap()))
            .collect()
    }

    fn cfg(&self, notify_extra: &str) -> Config {
        let tok = self.dir.path().join("afas.token");
        write_secret(&tok, b"ABCDEF0123456789");
        let d = self.dir.path().display();
        let text = config_toml(
            &self.afas.url(),
            &self.ms.url(),
            &self.dir.path().join("state"),
            &tok,
            "certificate",
            &Opts {
                max_invalid_percent: 100,
                ..Default::default()
            },
        ) + &format!(
            r#"
[notify]
gui_url = "https://sync.example.com"
{notify_extra}

[notify.email]
client_id = "{MAIL_APP}"
certificate_pem = "{cert}"
private_key_pem = "{d}/test-key.pem"
sender = "afas-sync@contoso.nl"

[[notify.channel]]
kind = "email"
name = "it-mail"
to = ["it@contoso.nl"]
personal_data = "names"

[[notify.channel]]
kind = "teams"
name = "teams"
url_file = "{d}/teams.url"

[[notify.channel]]
kind = "slack"
name = "slack"
url_file = "{d}/slack.url"

[[notify.channel]]
kind = "webhook"
name = "itsm"
url_file = "{d}/itsm.url"
secret_file = "{d}/hook.secret"
audience = ["hr"]
"#,
            cert = fixture("test-cert.pem"),
        );
        Config::parse(&text).unwrap_or_else(|e| panic!("{e}\n{text}"))
    }
}

fn go(cfg: &Config, apply: bool) -> RunResult {
    go_with(
        cfg,
        RunOptions {
            apply,
            ..Default::default()
        },
    )
}

/// Runs with the log capture installed, as `main` does.
fn go_with(cfg: &Config, mut o: RunOptions) -> RunResult {
    o.actor = "test".into();
    let sub = tracing_subscriber::registry().with(afas_entra_sync::logcap::Layer);
    tracing::subscriber::with_default(sub, || match run(cfg, &o, &|_| {}) {
        Ok(r) => r,
        Err((e, Some(rep))) => {
            eprintln!("run ended with: {e}");
            RunResult {
                report: *rep,
                plan: None,
                preview: None,
            }
        }
        Err((e, None)) => panic!("{e}"),
    })
}

fn by_path<'a>(msgs: &'a [(String, Value)], p: &str) -> Vec<&'a Value> {
    msgs.iter()
        .filter(|(x, _)| x.contains(p))
        .map(|(_, v)| v)
        .collect()
}

#[test]
fn a_failure_is_reported_once_on_every_channel_and_recovery_is_announced() {
    let mut env = Env::new();
    env.catch_all();
    env.afas_down();
    let cfg = env.cfg("");

    let r = go(&cfg, true);
    assert_eq!(r.report.exit_code, exit::SOURCE);
    assert_eq!(
        r.report.notifications.len(),
        4,
        "{:?}",
        r.report.notifications
    );
    assert!(
        r.report.notifications.iter().all(|d| d.ok),
        "{:?}",
        r.report.notifications
    );
    let m = env.take();
    assert_eq!(m.len(), 4, "email, Teams, Slack, webhook: {m:?}");

    // Email through Graph: HTML, high importance, the full log and the report attached.
    let mail = &by_path(&m, "sendMail")[0]["message"];
    assert!(
        mail["subject"]
            .as_str()
            .unwrap()
            .contains("Failed: The sync did not run: AFAS could not be read")
    );
    assert_eq!(mail["importance"], "high");
    assert_eq!(
        mail["toRecipients"][0]["emailAddress"]["address"],
        "it@contoso.nl"
    );
    let html = mail["body"]["content"].as_str().unwrap();
    // One point: what it means is the lead at the top, so the card does not repeat it.
    // (Once in the hidden inbox preview line, once as the lead.)
    assert_eq!(html.matches("new hires get no account").count(), 2);
    for part in [
        "What happened",
        "Why the tool does not fix this itself",
        "What to do",
        "status.afas.nl",
        "new hires get no account",
        "Open the admin GUI",
    ] {
        assert!(html.contains(part), "email lacks: {part}");
    }
    let names: Vec<&str> = mail["attachments"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["run.log", "report.json"]);
    use base64::Engine;
    let log = base64::engine::general_purpose::STANDARD
        .decode(mail["attachments"][0]["contentBytes"].as_str().unwrap())
        .unwrap();
    let log = String::from_utf8(log).unwrap();
    assert!(
        log.contains("sync started by test") && log.contains("AFAS"),
        "{log}"
    );

    // Teams: an Adaptive Card that says FAILED.
    let teams = by_path(&m, "/teams")[0];
    let card = &teams["attachments"][0]["content"];
    assert_eq!(card["type"], "AdaptiveCard");
    assert_eq!(card["body"][0]["style"], "attention");
    assert!(teams.to_string().contains("AFAS could not be read"));

    // Slack: blocks with the verdict; the log because it failed.
    let slack = by_path(&m, "/slack")[0];
    assert!(slack["text"].as_str().unwrap().starts_with("Failed"));
    assert!(slack.to_string().contains("Last "));

    // Webhook: signed (checked in the mock), with everything.
    let hook = by_path(&m, "/notify")[0];
    assert_eq!(hook["event"], "failure");
    assert_eq!(hook["findings"][0]["kind"], "run_failed");
    assert!(!hook["log"].as_array().unwrap().is_empty());
    // Employee numbers only on this channel: the report (data errors with their values) stays home.
    assert!(hook["report"].is_null());
    assert!(hook["facts"].to_string().contains("exit 30"));

    // The same failure again: nothing new, nobody is disturbed.
    let r = go(&cfg, true);
    assert!(r.report.notifications.iter().all(|d| d.event.is_none()));
    assert!(env.take().is_empty());

    // Fixed: "works again", once.
    env.rows(&[row("1", minus(400), None)]);
    env.upload_ok();
    let r = go(&cfg, true);
    assert_eq!(r.report.exit_code, exit::OK, "{:?}", r.report.result);
    let m = env.take();
    assert_eq!(
        m.len(),
        4,
        "everyone who heard about the failure hears it is over: {m:?}"
    );
    assert_eq!(by_path(&m, "/notify")[0]["event"], "recovered");
    let teams = by_path(&m, "/teams")[0].to_string();
    assert!(teams.contains("The sync works again") && teams.contains("AFAS could not be read"));
    assert!(
        teams.contains("failed run") || teams.contains("failing since"),
        "{teams}"
    );
    go(&cfg, true);
    assert!(env.take().is_empty(), "all quiet");
}

#[test]
fn points_of_attention_in_plain_language_with_names_only_where_allowed() {
    let mut env = Env::new();
    env.catch_all();
    let mut m1 = row("M1", minus(400), Some(minus(60)));
    m1.insert("Roepnaam".into(), json!("Mia"));
    m1.insert("Achternaam".into(), json!("de Groot"));
    let mut a = row("A1", minus(100), None);
    a.insert("Leidinggevende".into(), json!("M1"));
    let mut b = row("A2", minus(100), None);
    b.insert("Leidinggevende".into(), json!("M1"));
    let mut bad = row("X9", minus(100), None);
    bad.insert("UPN".into(), json!("x9@elsewhere.org"));
    env.rows(&[m1, a, b, bad]);
    env.upload_ok();
    let cfg = env.cfg("");
    let r = go(&cfg, true);
    assert_eq!(r.report.exit_code, exit::COMPLETED_WITH_EXCLUSIONS);
    let m = env.take();

    // The email channel allows names.
    let mail = by_path(&m, "sendMail")[0]["message"]["body"]["content"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(mail.contains("Mia de Groot (M1) left on"), "{mail}");
    assert!(mail.contains("2 employees still report to them"));
    assert!(mail.contains("HR: enter the new manager"));
    assert!(mail.contains("Who someone reports to is an HR decision"));
    assert!(mail.contains("skipped because of data errors"));
    assert!(mail.contains("Use one of the allowed domains in the UPN field: contoso.nl"));
    assert!(mail.contains("Voornaam") || mail.contains("A1"));

    // Teams and Slack get employee numbers only (the default).
    for p in ["/teams", "/slack"] {
        let s = by_path(&m, p)[0].to_string();
        assert!(
            s.contains("employee M1") || s.contains("Employee M1"),
            "{p}: {s}"
        );
        assert!(
            !s.contains("Mia") && !s.contains("de Groot"),
            "{p} must not name people"
        );
        assert!(!s.contains("Voornaam"), "{p} must not name people");
        assert!(
            !s.contains("x9@elsewhere.org") && !s.contains("@contoso.nl"),
            "{p} has no addresses: {s}"
        );
    }
    // The webhook is for HR only: the manager and data errors, nothing for IT.
    let hook = by_path(&m, "/notify")[0];
    let kinds: Vec<&str> = hook["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["kind"].as_str().unwrap())
        .collect();
    assert!(
        kinds.contains(&"manager_gone") && kinds.contains(&"excluded"),
        "{kinds:?}"
    );
    assert!(
        hook["findings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|f| f["new"] == true)
    );

    // Next run, nothing changed: quiet. A new point: only that one is marked new.
    go(&cfg, true);
    assert!(env.take().is_empty());
}

#[test]
fn a_test_run_only_notifies_on_request_and_remembers_nothing() {
    let mut env = Env::new();
    env.catch_all();
    let mut bad = row("X9", minus(100), None);
    bad.insert("UPN".into(), json!("x9@elsewhere.org"));
    env.rows(&[row("1", minus(400), None), bad]);
    let cfg = env.cfg("");
    go(&cfg, false);
    assert!(env.take().is_empty(), "a test run is quiet by default");
    let r = go_with(
        &cfg,
        RunOptions {
            notify: true,
            ..Default::default()
        },
    );
    assert!(!r.report.notifications.is_empty());
    let m = env.take();
    assert!(by_path(&m, "/teams")[0].to_string().contains("Test run"));
    // Asked again: sent again (nothing is remembered for test runs).
    go_with(
        &cfg,
        RunOptions {
            notify: true,
            ..Default::default()
        },
    );
    assert!(!env.take().is_empty());
}

#[test]
fn check_logs_reports_microsoft_failures_and_silence() {
    let mut env = Env::new();
    env.catch_all();
    env.ms
        .mock("GET", "/v1.0/auditLogs/provisioning")
        .match_query(Matcher::Any)
        .with_body(
            json!({ "value": [
                { "activityDateTime": "2026-11-03T09:10:00Z", "provisioningAction": "create",
                  "sourceIdentity": { "id": "10071" },
                  "provisioningStatusInfo": { "status": "failure", "errorInformation": { "reason": "AttributeValueMustBeUnique: userPrincipalName" } } }
            ]})
            .to_string(),
        )
        .create();
    let cfg = env.cfg("");
    let rep = check_logs(&cfg, 60, false, &|_| {});
    assert_eq!(rep.exit_code, exit::LOG_FAILURES);
    assert!(cfg.state.dir.join("last-check-logs.json").exists());
    let m = env.take();
    let teams = by_path(&m, "/teams")[0].to_string();
    assert!(
        teams.contains("Microsoft could not apply 1 record"),
        "{teams}"
    );
    assert!(
        teams.contains("sAMAccountName"),
        "the likely cause is explained"
    );
    // The HR webhook does not get provisioning errors.
    assert!(by_path(&m, "/notify").is_empty());
    // Same failure again: quiet.
    check_logs(&cfg, 60, false, &|_| {});
    assert!(env.take().is_empty());
}

#[test]
fn nothing_processed_after_an_upload_is_a_warning() {
    use afas_entra_sync::entra::LogSummary;
    use afas_entra_sync::sync::silence_warning;
    let env = Env::new();
    let cfg = env.cfg("");
    let t = |s: &str| {
        chrono::DateTime::parse_from_rfc3339(s)
            .unwrap()
            .with_timezone(&chrono::Utc)
    };
    let up = ("2026-11-03T09:07:00Z".to_string(), 12u64);
    let since = t("2026-11-03T08:30:00Z");
    let none = LogSummary::default();
    let w = silence_warning(&cfg, &none, Some(&up), since, t("2026-11-03T09:30:00Z")).unwrap();
    assert!(
        w.contains("uploaded 12 calls") && w.contains("quarantine"),
        "{w}"
    );
    // Too soon to tell, or outside the window, or processed: no warning.
    assert!(silence_warning(&cfg, &none, Some(&up), since, t("2026-11-03T09:12:00Z")).is_none());
    assert!(
        silence_warning(
            &cfg,
            &none,
            Some(&up),
            t("2026-11-03T09:20:00Z"),
            t("2026-11-03T09:30:00Z")
        )
        .is_none()
    );
    let seen = LogSummary {
        total: 12,
        latest_utc: Some("2026-11-03T09:08:30Z".into()),
        ..Default::default()
    };
    assert!(silence_warning(&cfg, &seen, Some(&up), since, t("2026-11-03T09:30:00Z")).is_none());
    assert!(silence_warning(&cfg, &none, None, since, t("2026-11-03T09:30:00Z")).is_none());
}

#[test]
fn a_channel_that_fails_is_retried_next_time_and_does_not_fail_the_run() {
    let mut env = Env::new();
    env.hook
        .mock("POST", "/teams")
        .with_status(500)
        .expect(2)
        .create();
    env.catch("hook", "POST", Matcher::Regex("^/(slack|notify)$".into()));
    env.catch("ms", "POST", Matcher::Regex("sendMail$".into()));
    env.afas_down();
    let cfg = env.cfg("");
    let r = go(&cfg, true);
    assert_eq!(
        r.report.exit_code,
        exit::SOURCE,
        "a notification never changes the exit code"
    );
    let teams = r
        .report
        .notifications
        .iter()
        .find(|d| d.channel == "teams")
        .unwrap();
    assert!(!teams.ok && teams.detail.contains("HTTP 500"), "{teams:?}");
    assert!(
        !teams.detail.contains("127.0.0.1"),
        "the URL is a secret: {}",
        teams.detail
    );
    env.take();
    // Next run: Teams still owes this failure, the others do not.
    let r = go(&cfg, true);
    let sent: Vec<&str> = r
        .report
        .notifications
        .iter()
        .filter(|d| d.event.is_some())
        .map(|d| d.channel.as_str())
        .collect();
    assert_eq!(sent, ["teams"]);
}

#[test]
fn notify_config_is_checked_on_load() {
    let env = Env::new();
    let d = env.dir.path().display();
    let tok = env.dir.path().join("afas.token");
    write_secret(&tok, b"ABCDEF0123456789");
    let base = config_toml(
        "http://127.0.0.1:1",
        "http://127.0.0.1:1",
        &env.dir.path().join("s"),
        &tok,
        "certificate",
        &Opts::default(),
    );
    let bad = [
        ("\n[notify]\n", "at least one"),
        (
            "\n[notify]\n[[notify.channel]]\nkind = \"slack\"\nurl = \"https://hooks.slack.com/services/x\"\n",
            "password",
        ),
        (
            &format!("\n[notify]\n[[notify.channel]]\nkind = \"webhook\"\nurl_file = \"{d}/x\"\n")
                as &str,
            "secret",
        ),
        (
            "\n[notify]\nrepeat_hours = 1000\n[[notify.channel]]\nkind = \"teams\"\nurl_env = \"X\"\n",
            "repeat_hours",
        ),
        (
            "\n[notify]\n[[notify.channel]]\nkind = \"email\"\nto = [\"a@b.nl\"]\n",
            "[notify.email]",
        ),
    ];
    for (extra, want) in bad {
        let e = Config::parse(&(base.clone() + extra))
            .unwrap_err()
            .to_string();
        assert!(e.contains(want), "{extra}: {e}");
    }
    // The GUI may never change where reports go.
    assert!(afas_entra_sync::config::is_locked("notify.channel"));
    assert!(afas_entra_sync::config::is_locked("entra.job_id"));
    assert!(afas_entra_sync::config::is_locked(
        "policy.allowed_upn_domains"
    ));
}
