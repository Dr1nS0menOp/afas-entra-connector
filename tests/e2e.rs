// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The afas-entra-sync Authors
//! End-to-end tests: the full run against simulated AFAS and Microsoft endpoints.
//! The mocks follow the documented behaviour (status codes, headers, paging).

mod common;

use afas_entra_sync::config::Config;
use afas_entra_sync::entra::{Credential, TokenProvider, read_logs};
use afas_entra_sync::error::{AppError, exit};
use afas_entra_sync::http::build_client;
use afas_entra_sync::sync::{RunOptions, RunResult, run};
use base64::Engine;
use chrono::{Days, NaiveDate};
use common::*;
use mockito::{Matcher, Mock, Server, ServerGuard};
use serde_json::{Map, Value, json};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const CONNECTOR_PATH: &str = "/ProfitRestServices/connectors/Entra_Medewerkers";

fn upload_path() -> String {
    format!("/v1.0/servicePrincipals/{SP}/synchronization/jobs/{JOB}/bulkUpload")
}

fn afas_auth() -> String {
    let xml = "<token><version>1</version><data>ABCDEF0123456789</data></token>";
    format!(
        "AfasToken {}",
        base64::engine::general_purpose::STANDARD.encode(xml)
    )
}

struct Env {
    afas: ServerGuard,
    entra: ServerGuard,
    dir: tempfile::TempDir,
    bodies: Arc<Mutex<Vec<Value>>>,
}

impl Env {
    fn new() -> Self {
        Self {
            afas: Server::new(),
            entra: Server::new(),
            dir: tempfile::tempdir().unwrap(),
            bodies: Arc::default(),
        }
    }
    fn cfg(&self, o: &Opts) -> Config {
        config(&self.afas.url(), &self.entra.url(), self.dir.path(), o)
    }
    /// AFAS returns all rows in one page (page_size 1000).
    fn afas_rows(&mut self, rows: &[Map<String, Value>]) -> Mock {
        self.afas
            .mock("GET", CONNECTOR_PATH)
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("skip".into(), "0".into()),
                Matcher::UrlEncoded("take".into(), "1000".into()),
                Matcher::UrlEncoded("orderbyfieldids".into(), "Personeelsnummer".into()),
            ]))
            .match_header("authorization", afas_auth().as_str())
            .with_status(200)
            .with_body(afas_body(rows))
            .create()
    }
    fn token(&mut self, hits: usize) -> Mock {
        self.entra
            .mock("POST", format!("/{TENANT}/oauth2/v2.0/token").as_str())
            .match_header("content-type", "application/x-www-form-urlencoded")
            .match_body(Matcher::AllOf(vec![
                Matcher::UrlEncoded("grant_type".into(), "client_credentials".into()),
                Matcher::UrlEncoded("client_id".into(), CLIENT.into()),
                Matcher::UrlEncoded(
                    "scope".into(),
                    "https://graph.microsoft.com/.default".into(),
                ),
                Matcher::UrlEncoded(
                    "client_assertion_type".into(),
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".into(),
                ),
                Matcher::Regex("client_assertion=ey".into()),
            ]))
            .with_status(200)
            .with_body(r#"{"token_type":"Bearer","expires_in":3599,"access_token":"tok1"}"#)
            .expect(hits)
            .create()
    }
    /// bulkUpload mock that records the received body.
    fn upload(&mut self, status: usize, hits: usize) -> Mock {
        let bodies = self.bodies.clone();
        self.entra
            .mock("POST", upload_path().as_str())
            .match_header("content-type", "application/scim+json")
            .match_header("authorization", "Bearer tok1")
            .with_status(status)
            .with_body_from_request(move |req| {
                if let Ok(b) = req.body()
                    && let Ok(v) = serde_json::from_slice::<Value>(b)
                {
                    bodies.lock().unwrap().push(v);
                }
                Vec::new()
            })
            .expect(hits)
            .create()
    }
    fn uploads_none(&mut self) -> Mock {
        self.entra.mock("POST", Matcher::Any).expect(0).create()
    }
    fn state_exists(&self) -> bool {
        self.dir.path().join("state").join("state.json").exists()
    }
    /// The report of the latest run (a sync and a test run each have their own file).
    fn report(&self) -> Value {
        let dir = self.dir.path().join("state");
        let newest = ["last-report.json", "last-dry-run-report.json"]
            .iter()
            .map(|f| dir.join(f))
            .filter(|p| p.exists())
            .max_by_key(|p| std::fs::metadata(p).and_then(|m| m.modified()).unwrap())
            .unwrap();
        serde_json::from_slice(&std::fs::read(newest).unwrap()).unwrap()
    }
}

fn opts(apply: bool) -> RunOptions {
    RunOptions {
        apply,
        as_of: None,
        allow_mass_disable: false,
        dump_payload: None,
        use_system_proxy: false,
        actor: "test".into(),
        ..Default::default()
    }
}

fn go(cfg: &Config, o: &RunOptions, sleeps: &SleepLog) -> Result<RunResult, AppError> {
    let f = sleeps.f();
    run(cfg, o, &f).map_err(|(e, _)| e)
}

fn employees(n: usize) -> Vec<Map<String, Value>> {
    let start = today_ams().checked_sub_days(Days::new(400)).unwrap();
    (1..=n)
        .map(|i| row(&format!("{i:05}"), start, None))
        .collect()
}

fn days_ago(n: u64) -> NaiveDate {
    today_ams().checked_sub_days(Days::new(n)).unwrap()
}

// ---------------------------------------------------------------------------

#[test]
fn dry_run_pages_through_afas_and_never_calls_entra() {
    let mut env = Env::new();
    let rows = employees(5);
    let auth = afas_auth();
    let mut pages = Vec::new();
    for (skip, chunk) in [(0usize, &rows[0..2]), (2, &rows[2..4]), (4, &rows[4..5])] {
        pages.push(
            env.afas
                .mock("GET", CONNECTOR_PATH)
                .match_query(Matcher::AllOf(vec![
                    Matcher::UrlEncoded("skip".into(), skip.to_string()),
                    Matcher::UrlEncoded("take".into(), "2".into()),
                ]))
                .match_header("authorization", auth.as_str())
                .with_body(afas_body(chunk))
                .expect(1)
                .create(),
        );
    }
    let none = env.uploads_none();
    let cfg = env.cfg(&Opts {
        page_size: 2,
        ..Default::default()
    });
    let sleeps = SleepLog::default();
    let r = go(&cfg, &opts(false), &sleeps).unwrap();
    assert_eq!(r.report.exit_code, exit::OK);
    assert_eq!(r.report.counts.rows_fetched, 5);
    assert_eq!(r.report.counts.sent_total, 5);
    assert_eq!(r.report.mode, "dry-run");
    for p in pages {
        p.assert();
    }
    none.assert();
    assert!(!env.state_exists(), "dry-run must not write state");
    assert_eq!(env.report()["exit_code"], 0);
}

#[test]
fn apply_happy_path_is_paced_and_idempotent() {
    let mut env = Env::new();
    let rows = employees(120);
    env.afas_rows(&rows).expect(2);
    let tok = env.token(2); // one token per run
    let up = env.upload(202, 6);
    let cfg = env.cfg(&Opts::default());
    let sleeps = SleepLog::default();

    let r1 = go(&cfg, &opts(true), &sleeps).unwrap();
    assert_eq!(r1.report.exit_code, exit::OK);
    assert_eq!(r1.report.upload.as_ref().unwrap().calls_accepted, 3);
    assert_eq!(
        sleeps.all(),
        vec![Duration::from_millis(125); 2],
        "pacing between calls, not after the last"
    );
    assert!(env.state_exists());
    let first: Vec<Value> = env.bodies.lock().unwrap().clone();

    let r2 = go(&cfg, &opts(true), &sleeps).unwrap();
    assert_eq!(r2.report.counts.new_disables, 0);
    let all = env.bodies.lock().unwrap().clone();
    assert_eq!(all.len(), 6);
    assert_eq!(&all[3..], &first[..], "second run sends exactly the same");

    let sizes: Vec<_> = first
        .iter()
        .map(|b| b["Operations"].as_array().unwrap().len())
        .collect();
    assert_eq!(sizes, [50, 50, 20]);
    let ids: Vec<String> = first
        .iter()
        .flat_map(|b| {
            b["Operations"]
                .as_array()
                .unwrap()
                .iter()
                .map(|o| o["data"]["externalId"].as_str().unwrap().to_string())
        })
        .collect();
    let expected: Vec<String> = (1..=120).map(|i| format!("{i:05}")).collect();
    assert_eq!(ids, expected);
    tok.assert();
    up.assert();
}

#[test]
fn retry_after_429_is_respected() {
    let mut env = Env::new();
    env.afas_rows(&employees(3));
    env.token(1);
    env.entra
        .mock("POST", upload_path().as_str())
        .with_status(429)
        .with_header("Retry-After", "3")
        .expect(1)
        .create();
    let ok = env.upload(202, 1);
    let sleeps = SleepLog::default();
    let r = go(&env.cfg(&Opts::default()), &opts(true), &sleeps).unwrap();
    assert_eq!(r.report.upload.unwrap().retries, 1);
    assert_eq!(sleeps.all(), vec![Duration::from_secs(3)]);
    ok.assert();
}

#[test]
fn retry_after_is_capped() {
    let mut env = Env::new();
    env.afas_rows(&employees(3));
    env.token(1);
    env.entra
        .mock("POST", upload_path().as_str())
        .with_status(429)
        .with_header("Retry-After", "99999")
        .expect(1)
        .create();
    env.upload(202, 1);
    let sleeps = SleepLog::default();
    go(&env.cfg(&Opts::default()), &opts(true), &sleeps).unwrap();
    assert_eq!(sleeps.all(), vec![Duration::from_secs(120)]);
}

#[test]
fn bucket_full_waits_five_minutes() {
    let mut env = Env::new();
    env.afas_rows(&employees(3));
    env.token(1);
    env.entra
        .mock("POST", upload_path().as_str())
        .with_status(500)
        .with_body(r#"{"error":{"message":"The bucket that stores the ingested data is full, please wait for the synchronization service to process the ingested data and retry this request."}}"#)
        .expect(1)
        .create();
    env.upload(202, 1);
    let sleeps = SleepLog::default();
    go(&env.cfg(&Opts::default()), &opts(true), &sleeps).unwrap();
    assert_eq!(sleeps.all(), vec![Duration::from_secs(300)]);
}

#[test]
fn server_errors_use_exponential_backoff() {
    let mut env = Env::new();
    env.afas_rows(&employees(3));
    env.token(1);
    env.entra
        .mock("POST", upload_path().as_str())
        .with_status(503)
        .expect(2)
        .create();
    env.upload(202, 1);
    let sleeps = SleepLog::default();
    let r = go(&env.cfg(&Opts::default()), &opts(true), &sleeps).unwrap();
    assert_eq!(r.report.upload.unwrap().retries, 2);
    assert_eq!(
        sleeps.all(),
        vec![Duration::from_secs(1), Duration::from_secs(2)]
    );
}

#[test]
fn unauthorized_refreshes_token_once() {
    let mut env = Env::new();
    env.afas_rows(&employees(3));
    let tok = env.token(2);
    env.entra
        .mock("POST", upload_path().as_str())
        .with_status(401)
        .expect(1)
        .create();
    env.upload(202, 1);
    let sleeps = SleepLog::default();
    go(&env.cfg(&Opts::default()), &opts(true), &sleeps).unwrap();
    tok.assert();
    assert!(sleeps.all().is_empty());
}

#[test]
fn repeated_unauthorized_is_fatal() {
    let mut env = Env::new();
    env.afas_rows(&employees(3));
    env.token(2);
    env.entra
        .mock("POST", upload_path().as_str())
        .with_status(401)
        .expect(2)
        .create();
    let err = go(
        &env.cfg(&Opts::default()),
        &opts(true),
        &SleepLog::default(),
    )
    .unwrap_err();
    assert_eq!(err.exit_code(), exit::UPLOAD);
    assert!(!env.state_exists());
}

#[test]
fn bad_request_stops_and_keeps_old_state() {
    let mut env = Env::new();
    env.afas_rows(&employees(60));
    env.token(1);
    env.upload(202, 1);
    env.entra
        .mock("POST", upload_path().as_str())
        .with_status(400)
        .with_body(r#"{"error":"schema"}"#)
        .expect(1)
        .create();
    let err = go(
        &env.cfg(&Opts::default()),
        &opts(true),
        &SleepLog::default(),
    )
    .unwrap_err();
    let msg = err.to_string();
    assert_eq!(err.exit_code(), exit::UPLOAD);
    assert!(
        msg.contains("call 2/2") && msg.contains("calls 1..1 were accepted"),
        "{msg}"
    );
    assert!(!env.state_exists(), "no new state after a failed upload");
    assert_eq!(env.report()["exit_code"], exit::UPLOAD);
}

#[test]
fn gives_up_after_max_attempts() {
    let mut env = Env::new();
    env.afas_rows(&employees(3));
    env.token(1);
    let m = env
        .entra
        .mock("POST", upload_path().as_str())
        .with_status(503)
        .expect(4)
        .create();
    let sleeps = SleepLog::default();
    let err = go(&env.cfg(&Opts::default()), &opts(true), &sleeps).unwrap_err();
    assert_eq!(err.exit_code(), exit::UPLOAD);
    assert_eq!(sleeps.all().len(), 3);
    m.assert();
}

#[test]
fn guard_violation_uploads_nothing() {
    let mut env = Env::new();
    env.afas_rows(&employees(3));
    let none = env.uploads_none();
    let err = go(
        &env.cfg(&Opts {
            min_records: 50,
            ..Default::default()
        }),
        &opts(true),
        &SleepLog::default(),
    )
    .unwrap_err();
    assert_eq!(err.exit_code(), exit::GUARD);
    assert!(err.to_string().contains("min_records"));
    none.assert();
    assert_eq!(env.report()["exit_code"], exit::GUARD);
}

#[test]
fn empty_afas_response_is_stopped() {
    let mut env = Env::new();
    env.afas_rows(&[]);
    let none = env.uploads_none();
    let err = go(
        &env.cfg(&Opts::default()),
        &opts(true),
        &SleepLog::default(),
    )
    .unwrap_err();
    assert_eq!(err.exit_code(), exit::GUARD);
    none.assert();
}

#[test]
fn mass_disable_needs_explicit_flag() {
    let mut env = Env::new();
    let mut rows = employees(20);
    env.afas_rows(&rows).expect(1);
    env.token(2);
    let cfg = env.cfg(&Opts {
        max_disables: 2,
        ..Default::default()
    });
    env.upload(202, 2);
    go(&cfg, &opts(true), &SleepLog::default()).unwrap(); // first run: everyone active

    for (i, r) in rows.iter_mut().enumerate().take(3) {
        *r = row(&format!("{:05}", i + 1), days_ago(400), Some(days_ago(2)));
    }
    env.afas.reset();
    env.afas_rows(&rows).expect(2);
    let err = go(&cfg, &opts(true), &SleepLog::default()).unwrap_err();
    assert_eq!(err.exit_code(), exit::GUARD);
    assert!(err.to_string().contains("3 accounts"));
    assert_eq!(
        env.bodies.lock().unwrap().len(),
        1,
        "nothing uploaded after the stop"
    );

    let mut o = opts(true);
    o.allow_mass_disable = true;
    let r = go(&cfg, &o, &SleepLog::default()).unwrap();
    assert_eq!(r.report.counts.new_disables, 3);
    let last = env.bodies.lock().unwrap().last().unwrap().clone();
    let inactive = last["Operations"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|o| o["data"]["active"] == false)
        .count();
    assert_eq!(inactive, 3);
}

#[test]
fn drop_against_previous_run_is_stopped() {
    let mut env = Env::new();
    env.afas_rows(&employees(100)).expect(1);
    env.token(1);
    env.upload(202, 2);
    let cfg = env.cfg(&Opts::default());
    go(&cfg, &opts(true), &SleepLog::default()).unwrap();
    env.afas.reset();
    env.afas_rows(&employees(80));
    let err = go(&cfg, &opts(true), &SleepLog::default()).unwrap_err();
    assert_eq!(err.exit_code(), exit::GUARD);
    assert!(err.to_string().contains("max_drop_percent"));
}

#[test]
fn missing_afas_field_is_fatal() {
    let mut env = Env::new();
    let mut rows = employees(3);
    rows[1].remove("Afdeling");
    env.afas_rows(&rows);
    let none = env.uploads_none();
    let err = go(
        &env.cfg(&Opts::default()),
        &opts(true),
        &SleepLog::default(),
    )
    .unwrap_err();
    assert_eq!(err.exit_code(), exit::SOURCE);
    assert!(err.to_string().contains("Afdeling"));
    none.assert();
}

#[test]
fn afas_auth_error_is_not_retried() {
    let mut env = Env::new();
    let m = env
        .afas
        .mock("GET", Matcher::Any)
        .with_status(401)
        .with_body("token invalid")
        .expect(1)
        .create();
    let sleeps = SleepLog::default();
    let err = go(&env.cfg(&Opts::default()), &opts(false), &sleeps).unwrap_err();
    assert_eq!(err.exit_code(), exit::SOURCE);
    assert!(sleeps.all().is_empty());
    m.assert();
}

#[test]
fn afas_server_error_is_retried() {
    let mut env = Env::new();
    env.afas
        .mock("GET", Matcher::Any)
        .with_status(503)
        .expect(1)
        .create();
    env.afas_rows(&employees(3));
    let sleeps = SleepLog::default();
    let r = go(&env.cfg(&Opts::default()), &opts(false), &sleeps).unwrap();
    assert_eq!(r.report.counts.sent_total, 3);
    assert_eq!(sleeps.all(), vec![Duration::from_secs(2)]);
}

#[test]
fn afas_ignoring_skip_is_detected() {
    let mut env = Env::new();
    let rows = employees(2);
    env.afas
        .mock("GET", CONNECTOR_PATH)
        .match_query(Matcher::Any)
        .with_body(afas_body(&rows))
        .create();
    let err = go(
        &env.cfg(&Opts {
            page_size: 2,
            ..Default::default()
        }),
        &opts(false),
        &SleepLog::default(),
    )
    .unwrap_err();
    assert_eq!(err.exit_code(), exit::SOURCE);
    assert!(err.to_string().contains("the same page"));
}

#[test]
fn afas_garbage_responses_are_rejected() {
    for body in [
        "<html>maintenance</html>",
        "[]",
        r#"{"rijen":[]}"#,
        r#"{"rows":[1,2]}"#,
    ] {
        let mut env = Env::new();
        env.afas.mock("GET", Matcher::Any).with_body(body).create();
        let err = go(
            &env.cfg(&Opts::default()),
            &opts(false),
            &SleepLog::default(),
        )
        .unwrap_err();
        assert_eq!(err.exit_code(), exit::SOURCE, "{body}");
    }
}

#[test]
fn token_rejection_is_auth_error_and_uploads_nothing() {
    let mut env = Env::new();
    env.afas_rows(&employees(3));
    env.entra
        .mock("POST", format!("/{TENANT}/oauth2/v2.0/token").as_str())
        .with_status(401)
        .with_body(r#"{"error":"invalid_client","error_description":"AADSTS700027: Client assertion contains an invalid signature."}"#)
        .create();
    let none = env
        .entra
        .mock("POST", upload_path().as_str())
        .expect(0)
        .create();
    let err = go(
        &env.cfg(&Opts::default()),
        &opts(true),
        &SleepLog::default(),
    )
    .unwrap_err();
    assert_eq!(err.exit_code(), exit::AUTH);
    assert!(err.to_string().contains("AADSTS700027"));
    none.assert();
}

#[test]
fn exclusions_give_exit_3_and_are_reported() {
    let mut env = Env::new();
    let mut rows = employees(30);
    rows[4].insert("UPN".into(), json!("iemand@gmail.com"));
    env.afas_rows(&rows);
    let r = go(
        &env.cfg(&Opts::default()),
        &opts(false),
        &SleepLog::default(),
    )
    .unwrap();
    assert_eq!(r.report.exit_code, exit::COMPLETED_WITH_EXCLUSIONS);
    assert_eq!(r.report.exclusions[0].employee_id.as_deref(), Some("00005"));
    assert_eq!(r.report.counts.sent_total, 29);
    let rep = env.report();
    assert_eq!(rep["exit_code"], 3);
    assert!(
        !rep.to_string().contains("Voornaam00005"),
        "report contains no names"
    );
}

#[test]
fn concurrent_run_is_refused() {
    let env = Env::new();
    let cfg = env.cfg(&Opts::default());
    let store = afas_entra_sync::state::StateStore::new(&cfg.state.dir).unwrap();
    let _held = store.lock().unwrap();
    let err = go(&cfg, &opts(false), &SleepLog::default()).unwrap_err();
    assert_eq!(err.exit_code(), exit::LOCKED);
}

#[test]
fn as_of_cannot_be_combined_with_apply() {
    let env = Env::new();
    let mut o = opts(true);
    o.as_of = Some(d("2030-01-01"));
    let err = go(&env.cfg(&Opts::default()), &o, &SleepLog::default()).unwrap_err();
    assert_eq!(err.exit_code(), exit::CONFIG);
}

#[test]
fn as_of_changes_the_dry_run_date() {
    let mut env = Env::new();
    env.afas_rows(&[row("1", d("2030-01-10"), None)]);
    let mut o = opts(false);
    o.as_of = Some(d("2030-01-01"));
    let r = go(&env.cfg(&Opts::default()), &o, &SleepLog::default()).unwrap();
    assert_eq!(r.report.today, "2030-01-01");
    assert_eq!(r.report.counts.sent_inactive_prehire, 1);
}

#[test]
fn dump_payload_equals_what_is_uploaded() {
    let mut env = Env::new();
    env.afas_rows(&employees(70));
    env.token(1);
    env.upload(202, 2);
    let mut o = opts(true);
    let dump = env.dir.path().join("payload.json");
    o.dump_payload = Some(dump.clone());
    go(&env.cfg(&Opts::default()), &o, &SleepLog::default()).unwrap();
    let dumped: Vec<Value> = serde_json::from_slice(&std::fs::read(dump).unwrap()).unwrap();
    assert_eq!(dumped, *env.bodies.lock().unwrap());
}

#[test]
fn corrupt_state_blocks_the_run() {
    let mut env = Env::new();
    env.afas_rows(&employees(3));
    let none = env.uploads_none();
    let cfg = env.cfg(&Opts::default());
    std::fs::create_dir_all(&cfg.state.dir).unwrap();
    std::fs::write(cfg.state.dir.join("state.json"), "{").unwrap();
    let err = go(&cfg, &opts(true), &SleepLog::default()).unwrap_err();
    assert_eq!(err.exit_code(), exit::CONFIG);
    none.assert();
}

// ---------------------------------------------------------------------------
// Provisioning logs

fn log_item(status: &str, id: &str) -> Value {
    json!({
        "activityDateTime": "2026-10-30T10:00:00Z",
        "provisioningAction": "create",
        "sourceIdentity": {"id": id},
        "provisioningStatusInfo": {"status": status, "errorInformation": {"reason": format!("reason {id}")}}
    })
}

#[test]
fn logs_are_paged_and_failures_counted() {
    let mut env = Env::new();
    env.token(1);
    let base = env.entra.url();
    env.entra
        .mock("GET", "/v1.0/auditLogs/provisioning")
        .match_query(Matcher::AllOf(vec![
            Matcher::UrlEncoded("$filter".into(), format!("jobId eq '{JOB}' and activityDateTime ge 2026-10-30T08:00:00Z")),
            Matcher::UrlEncoded("$top".into(), "500".into()),
        ]))
        .match_header("authorization", "Bearer tok1")
        .with_body(json!({"value": [log_item("success", "1"), log_item("failure", "2")],
                          "@odata.nextLink": format!("{base}/v1.0/auditLogs/provisioning?$skiptoken=abc")}).to_string())
        .create();
    env.entra
        .mock("GET", "/v1.0/auditLogs/provisioning")
        .match_query(Matcher::UrlEncoded("$skiptoken".into(), "abc".into()))
        .with_body(json!({"value": [log_item("skipped", "3"), log_item("warning", "4"), log_item("failure", "5"), log_item("unknownFutureValue", "6")]}).to_string())
        .create();
    let cfg = env.cfg(&Opts::default());
    let client = build_client(5, false, &Default::default()).unwrap();
    let cred = Credential::from_config(&cfg.entra).unwrap();
    let sleep = |_d: Duration| {};
    let tokens = TokenProvider::new(&cfg.entra, &client, cred, &sleep);
    let since = chrono::DateTime::parse_from_rfc3339("2026-10-30T08:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let s = read_logs(&cfg.entra, &client, &tokens, since).unwrap();
    assert_eq!(
        (s.total, s.success, s.failure, s.skipped, s.warning, s.other),
        (6, 1, 2, 1, 1, 1)
    );
    assert_eq!(s.failures.len(), 2);
    assert_eq!(
        (
            s.failures[0].source_id.as_str(),
            s.failures[0].action.as_str()
        ),
        ("2", "create")
    );
    assert_eq!(s.failures[1].source_id, "5");
    assert_eq!(s.failures[1].reason, "reason 5");
}

#[test]
fn logs_refuse_foreign_next_link() {
    let mut env = Env::new();
    env.token(1);
    env.entra
        .mock("GET", "/v1.0/auditLogs/provisioning")
        .match_query(Matcher::Any)
        .with_body(
            json!({"value": [], "@odata.nextLink": "https://evil.example/steal"}).to_string(),
        )
        .create();
    let cfg = env.cfg(&Opts::default());
    let client = build_client(5, false, &Default::default()).unwrap();
    let cred = Credential::from_config(&cfg.entra).unwrap();
    let sleep = |_d: Duration| {};
    let tokens = TokenProvider::new(&cfg.entra, &client, cred, &sleep);
    let err = read_logs(&cfg.entra, &client, &tokens, chrono::Utc::now()).unwrap_err();
    assert!(err.to_string().contains("different host"));
}

#[test]
fn employee_vanishing_from_afas_is_flagged_not_silently_ignored() {
    let mut env = Env::new();
    let mut rows = employees(20);
    env.afas_rows(&rows).expect(1);
    env.token(2);
    env.upload(202, 2);
    let cfg = env.cfg(&Opts::default());
    go(&cfg, &opts(true), &SleepLog::default()).unwrap();
    rows.remove(6); // 00007 disappears from the GetConnector
    env.afas.reset();
    env.afas_rows(&rows);
    let r = go(&cfg, &opts(true), &SleepLog::default()).unwrap();
    assert_eq!(r.report.exit_code, exit::COMPLETED_WITH_EXCLUSIONS);
    assert_eq!(r.report.disappeared_while_active, vec!["00007".to_string()]);
    assert_eq!(env.report()["disappeared_while_active"][0], "00007");
}

#[test]
fn afas_persistent_server_error_gives_up_after_max_attempts() {
    let mut env = Env::new();
    let m = env
        .afas
        .mock("GET", Matcher::Any)
        .with_status(503)
        .expect(3)
        .create();
    let sleeps = SleepLog::default();
    let err = go(&env.cfg(&Opts::default()), &opts(false), &sleeps).unwrap_err();
    assert_eq!(err.exit_code(), exit::SOURCE);
    assert!(err.to_string().contains("after 3 attempts"), "{err}");
    assert_eq!(
        sleeps.all(),
        vec![Duration::from_secs(2), Duration::from_secs(4)]
    );
    m.assert();
}

#[test]
fn afas_unreachable_is_retried_then_reported() {
    // Port that is guaranteed closed: bind, remember the address, close the socket.
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(
        &format!("http://127.0.0.1:{port}"),
        "http://127.0.0.1:1",
        dir.path(),
        &Opts::default(),
    );
    let sleeps = SleepLog::default();
    let err = go(&cfg, &opts(false), &sleeps).unwrap_err();
    let msg = err.to_string();
    assert_eq!(err.exit_code(), exit::SOURCE);
    assert!(
        msg.contains("after 3 attempts") && msg.contains("network error"),
        "{msg}"
    );
    assert!(
        msg.contains("<url>") && !msg.contains(&port.to_string()),
        "URL is shortened: {msg}"
    );
    assert_eq!(sleeps.all().len(), 2);
}

#[test]
fn token_close_to_expiry_is_renewed_before_each_call() {
    let mut env = Env::new();
    env.afas_rows(&employees(120)); // 3 calls
    // valid for 200 s: within the 5-minute margin, so refresh every time.
    let tok = env
        .entra
        .mock("POST", format!("/{TENANT}/oauth2/v2.0/token").as_str())
        .with_body(r#"{"access_token":"tok1","expires_in":200}"#)
        .expect(4) // 1 up front + 1 per call
        .create();
    env.upload(202, 3);
    go(
        &env.cfg(&Opts::default()),
        &opts(true),
        &SleepLog::default(),
    )
    .unwrap();
    tok.assert();
}

#[test]
fn token_endpoint_outage_is_retried_then_auth_error() {
    let mut env = Env::new();
    env.afas_rows(&employees(3));
    let t = env
        .entra
        .mock("POST", format!("/{TENANT}/oauth2/v2.0/token").as_str())
        .with_status(503)
        .expect(4)
        .create();
    let none = env
        .entra
        .mock("POST", upload_path().as_str())
        .expect(0)
        .create();
    let sleeps = SleepLog::default();
    let err = go(&env.cfg(&Opts::default()), &opts(true), &sleeps).unwrap_err();
    assert_eq!(err.exit_code(), exit::AUTH);
    assert!(err.to_string().contains("after 4 attempts"), "{err}");
    assert_eq!(
        sleeps.all(),
        vec![
            Duration::from_secs(2),
            Duration::from_secs(4),
            Duration::from_secs(8)
        ]
    );
    t.assert();
    none.assert();
}

#[test]
fn token_endpoint_throttling_is_retried() {
    let mut env = Env::new();
    env.afas_rows(&employees(3));
    env.entra
        .mock("POST", format!("/{TENANT}/oauth2/v2.0/token").as_str())
        .with_status(429)
        .expect(1)
        .create();
    env.token(1);
    env.upload(202, 1);
    let sleeps = SleepLog::default();
    go(&env.cfg(&Opts::default()), &opts(true), &sleeps).unwrap();
    assert_eq!(sleeps.all(), vec![Duration::from_secs(2)]);
}

#[test]
fn plain_500_uses_backoff_not_bucket_wait() {
    let mut env = Env::new();
    env.afas_rows(&employees(3));
    env.token(1);
    env.entra
        .mock("POST", upload_path().as_str())
        .with_status(500)
        .with_body(r#"{"error":"internal"}"#)
        .expect(1)
        .create();
    // 400 with the word 'bucket' stays a hard error
    env.upload(202, 1);
    let sleeps = SleepLog::default();
    go(&env.cfg(&Opts::default()), &opts(true), &sleeps).unwrap();
    assert_eq!(sleeps.all(), vec![Duration::from_secs(1)]);
}

#[test]
fn client_error_mentioning_bucket_is_still_fatal() {
    let mut env = Env::new();
    env.afas_rows(&employees(3));
    env.token(1);
    env.entra
        .mock("POST", upload_path().as_str())
        .with_status(400)
        .with_body("bucket")
        .expect(1)
        .create();
    let sleeps = SleepLog::default();
    let err = go(&env.cfg(&Opts::default()), &opts(true), &sleeps).unwrap_err();
    assert_eq!(err.exit_code(), exit::UPLOAD);
    assert!(sleeps.all().is_empty());
}

#[test]
fn zero_pace_means_no_pauses() {
    let mut env = Env::new();
    env.afas_rows(&employees(120));
    env.token(1);
    env.upload(202, 3);
    let token = env.dir.path().join("afas.token");
    write_secret(&token, b"ABCDEF0123456789");
    let toml = config_toml(
        &env.afas.url(),
        &env.entra.url(),
        &env.dir.path().join("state"),
        &token,
        "certificate",
        &Opts::default(),
    )
    .replace("pace_ms = 125", "pace_ms = 0");
    let cfg = Config::parse(&toml).unwrap();
    let sleeps = SleepLog::default();
    go(&cfg, &opts(true), &sleeps).unwrap();
    assert!(sleeps.all().is_empty(), "{:?}", sleeps.all());
}

#[test]
fn redirects_are_not_followed() {
    let mut env = Env::new();
    let target = format!("{}/elders", env.afas.url());
    env.afas
        .mock("GET", CONNECTOR_PATH)
        .match_query(Matcher::Any)
        .with_status(302)
        .with_header("Location", &target)
        .create();
    let elders = env
        .afas
        .mock("GET", "/elders")
        .with_body(afas_body(&employees(3)))
        .expect(0)
        .create();
    let err = go(
        &env.cfg(&Opts::default()),
        &opts(false),
        &SleepLog::default(),
    )
    .unwrap_err();
    assert_eq!(err.exit_code(), exit::SOURCE);
    assert!(err.to_string().contains("302"), "{err}");
    elders.assert();
}

#[test]
fn hanging_server_is_cut_off_by_timeout() {
    // Server that accepts connections but never answers.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for s in listener.incoming().flatten() {
            held.push(s); // keep open, send nothing
        }
    });
    let dir = tempfile::tempdir().unwrap();
    let token = dir.path().join("afas.token");
    write_secret(&token, b"ABCDEF0123456789");
    let toml = config_toml(
        &format!("http://127.0.0.1:{port}"),
        "http://127.0.0.1:1",
        &dir.path().join("state"),
        &token,
        "certificate",
        &Opts::default(),
    )
    .replacen("timeout_secs = 5", "timeout_secs = 1", 1);
    let cfg = Config::parse(&toml).unwrap();
    assert_eq!(cfg.afas.timeout_secs, 1);
    let started = std::time::Instant::now();
    let err = go(&cfg, &opts(false), &SleepLog::default()).unwrap_err();
    assert_eq!(err.exit_code(), exit::SOURCE);
    assert!(
        started.elapsed() < Duration::from_secs(15),
        "took {:?}",
        started.elapsed()
    );
}
