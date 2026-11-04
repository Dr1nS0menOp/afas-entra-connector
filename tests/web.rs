// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The afas-entra-sync Authors
//! Tests for the admin GUI through `web::handle` (without networking).

mod common;

use afas_entra_sync::config::{Config, check_overrides};
use afas_entra_sync::web::{
    App, CONFIRM_APPLY, CONFIRM_MASS, MAX_SESSIONS, Request, Response, SESSION_COOKIE, WebOptions,
    esc, handle, parse_form, validate_listen,
};
use common::*;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering;

const EXTRA: &str = "\n[afas.fields.extra]\nphone_work = { enabled = true, field = \"TelWerk\" }\noffice = { enabled = false, field = \"Standplaats\" }\n";
const GUI_ON: &str = "\n[gui]\nenabled = true\n";

struct Env {
    dir: tempfile::TempDir,
    cfg_path: PathBuf,
}

impl Env {
    fn state(&self, f: &str) -> PathBuf {
        self.dir.path().join("state").join(f)
    }
}

fn env_with(afas: &str, entra: &str, extra_toml: &str) -> Env {
    let dir = tempfile::tempdir().unwrap();
    let tok = dir.path().join("afas.token");
    write_secret(&tok, b"ABCDEF0123456789");
    let toml = config_toml(
        afas,
        entra,
        &dir.path().join("state"),
        &tok,
        "certificate",
        &Opts::default(),
    ) + extra_toml;
    let cfg_path = dir.path().join("config.toml");
    std::fs::write(&cfg_path, toml).unwrap();
    std::fs::create_dir_all(dir.path().join("state")).unwrap();
    Env { dir, cfg_path }
}

fn env(afas: &str) -> Env {
    env_with(afas, "http://127.0.0.1:1", &format!("{EXTRA}{GUI_ON}"))
}

fn opts(e: &Env, read_only: bool, proxy: Option<IpAddr>) -> WebOptions {
    WebOptions {
        config_path: e.cfg_path.clone(),
        listen: if proxy.is_some() {
            "0.0.0.0:8080".parse().unwrap()
        } else {
            "127.0.0.1:8080".parse().unwrap()
        },
        read_only,
        trusted_proxy: proxy,
    }
}

fn app(e: &Env, read_only: bool, proxy: Option<IpAddr>) -> App {
    let mut a = App::new(opts(e, read_only, proxy)).unwrap();
    a.sleep = Arc::new(|_| {});
    a.use_system_proxy = false;
    a.run_inline = true;
    a
}

/// Headers of a signed-in local browser session.
fn auth(a: &App) -> Vec<(String, String)> {
    vec![
        ("host".into(), "127.0.0.1:8080".into()),
        (
            "cookie".into(),
            format!("other=1; {SESSION_COOKIE}={}", a.new_session().unwrap()),
        ),
    ]
}

fn get(a: &App, path: &str) -> Response {
    handle(
        a,
        &Request {
            method: "GET",
            path,
            remote: Some("127.0.0.1".parse().unwrap()),
            headers: &auth(a),
            body: b"",
        },
    )
}

fn post(a: &App, path: &str, body: &str) -> Response {
    handle(
        a,
        &Request {
            method: "POST",
            path,
            remote: Some("127.0.0.1".parse().unwrap()),
            headers: &auth(a),
            body: body.as_bytes(),
        },
    )
}

fn csrf(a: &App) -> String {
    format!("csrf={}", a.csrf)
}

// ------------------------------------------------------------------ switch

#[test]
fn gui_is_off_by_default_and_refuses_to_start() {
    let e = env_with("http://127.0.0.1:1", "http://127.0.0.1:1", EXTRA);
    let err = App::new(opts(&e, false, None)).err().unwrap();
    assert!(err.contains("GUI is off"), "{err}");
    let e = env_with(
        "http://127.0.0.1:1",
        "http://127.0.0.1:1",
        "\n[gui]\nenabled = false\n",
    );
    assert!(App::new(opts(&e, false, None)).is_err());
}

#[test]
fn switching_off_in_config_stops_a_running_gui() {
    let e = env("http://127.0.0.1:1");
    let a = app(&e, false, None);
    assert_eq!(get(&a, "/").status, 200);
    let t = std::fs::read_to_string(&e.cfg_path)
        .unwrap()
        .replace("enabled = true\n", "enabled = false\n");
    // only the [gui] line is at the end; the toggles use inline tables
    std::fs::write(&e.cfg_path, t).unwrap();
    let r = get(&a, "/");
    assert_eq!(r.status, 503);
    assert!(a.shutdown.load(Ordering::SeqCst), "server must stop");
}

#[test]
fn gui_can_switch_itself_off_but_never_on() {
    let e = env("http://127.0.0.1:1");
    let a = app(&e, false, None);
    assert_eq!(post(&a, "/gui/off", &csrf(&a)).status, 200);
    assert!(a.shutdown.load(Ordering::SeqCst));
    assert!(!Config::load(&e.cfg_path).unwrap().gui.enabled);
    assert!(
        App::new(opts(&e, false, None)).is_err(),
        "after turning off, the GUI no longer starts"
    );
    // A GUI layer that turns the GUI on is refused.
    let ov: toml::Table = "[gui]\nenabled = true\n".parse().unwrap();
    assert!(check_overrides(&ov).is_err());
    std::fs::write(e.state("overrides.toml"), "[gui]\nenabled = true\n").unwrap();
    assert!(Config::load(&e.cfg_path).is_err());
}

#[test]
fn gui_enable_cli_restores_access() {
    let e = env("http://127.0.0.1:1");
    let a = app(&e, false, None);
    post(&a, "/gui/off", &csrf(&a));
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_afas-entra-sync"))
        .args(["-c", e.cfg_path.to_str().unwrap(), "gui-enable"])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(App::new(opts(&e, false, None)).is_ok());
    // If it is off in the base file, gui-enable does not help.
    let e2 = env_with("http://127.0.0.1:1", "http://127.0.0.1:1", EXTRA);
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_afas-entra-sync"))
        .args(["-c", e2.cfg_path.to_str().unwrap(), "gui-enable"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(10));
}

// ------------------------------------------------------------------ access

#[test]
fn non_loopback_requires_trusted_proxy() {
    let e = env("http://127.0.0.1:1");
    let mut o = opts(&e, false, None);
    o.listen = "0.0.0.0:8080".parse().unwrap();
    assert!(validate_listen(&o).is_err());
}

#[test]
fn proxy_mode_checks_source_and_user_header() {
    let e = env("http://127.0.0.1:1");
    let proxy: IpAddr = "10.0.0.5".parse().unwrap();
    let a = app(&e, false, Some(proxy));
    let user = vec![("x-authentik-username".to_string(), "jdoe".to_string())];
    let r = |remote: &str, h: &[(String, String)]| {
        handle(
            &a,
            &Request {
                method: "GET",
                path: "/",
                remote: Some(remote.parse().unwrap()),
                headers: h,
                body: b"",
            },
        )
        .status
    };
    assert_eq!(r("10.0.0.9", &user), 403);
    assert_eq!(r("10.0.0.5", &[]), 403);
    assert_eq!(r("10.0.0.5", &user), 200);
}

#[test]
fn csrf_read_only_size_and_methods() {
    let e = env("http://127.0.0.1:1");
    let a = app(&e, false, None);
    assert_eq!(
        post(&a, "/settings/upload", "upload.pace_ms=500").status,
        403
    );
    assert_eq!(
        post(&a, "/settings/upload", "csrf=wrong&upload.pace_ms=500").status,
        403
    );
    let big = format!("{}&x={}", csrf(&a), "a".repeat(70_000));
    assert_eq!(post(&a, "/settings/upload", &big).status, 413);
    assert_eq!(
        handle(
            &a,
            &Request {
                method: "PUT",
                path: "/",
                remote: None,
                headers: &auth(&a),
                body: b""
            }
        )
        .status,
        405
    );
    let ro = app(&e, true, None);
    assert_eq!(
        post(
            &ro,
            "/settings/upload",
            &format!("{}&upload.pace_ms=500", csrf(&ro))
        )
        .status,
        403
    );
    assert!(!get(&ro, "/settings/upload").text().contains("Save changes"));
    assert!(!e.state("overrides.toml").exists());
}

// ------------------------------------------------------------------ pages

#[test]
fn every_page_renders() {
    let e = env("http://127.0.0.1:1");
    let a = app(&e, false, None);
    for p in [
        "/",
        "/run",
        "/audit",
        "/gui",
        "/health",
        "/settings/source",
        "/settings/fields",
        "/settings/attributes",
        "/settings/entra",
        "/settings/safety",
        "/settings/upload",
        "/settings/population",
        "/settings/tls",
    ] {
        let r = get(&a, p);
        assert_eq!(r.status, 200, "{p}: {}", r.text());
    }
    assert_eq!(get(&a, "/settings/does-not-exist").status, 404);
    assert_eq!(get(&a, "/payload").status, 404);
}

#[test]
fn locked_fields_are_shown_readonly_and_cannot_be_changed() {
    let e = env("http://127.0.0.1:1");
    let a = app(&e, false, None);
    let page = get(&a, "/settings/entra").text();
    assert!(page.contains("fixed in config file"));
    // An attempt to change graph_base is ignored (the field is locked).
    let r = post(
        &a,
        "/settings/entra",
        &format!(
            "{}&entra.graph_base=https://evil.example&entra.service_principal_id={SP}&entra.job_id={JOB}&entra.timeout_secs=5",
            csrf(&a)
        ),
    );
    assert_eq!(r.status, 303);
    assert_eq!(
        Config::load(&e.cfg_path).unwrap().entra.graph_base,
        "http://127.0.0.1:1/v1.0"
    );
    // And a hand-written GUI layer with a locked key makes the config invalid.
    std::fs::write(
        e.state("overrides.toml"),
        "[entra]\ngraph_base = \"https://evil.example\"\n",
    )
    .unwrap();
    assert!(Config::load(&e.cfg_path).is_err());
}

// ------------------------------------------------------------------ settings

#[test]
fn settings_roundtrip_is_validated_audited_and_reversible() {
    let e = env("http://127.0.0.1:1");
    let a = app(&e, false, None);
    let form = |min: &str| {
        format!(
            "{}&policy.timezone=Europe%2FAmsterdam&policy.allowed_upn_domains=contoso.nl%2C+example.com&policy.prehire_days=30&policy.leaver_lookback_days=30&policy.min_records={min}&policy.max_drop_percent=10&policy.max_disables_per_run=10&policy.max_invalid_percent=10&policy.max_calls_per_run=100&policy.max_new_per_run=25&policy.max_upn_changes_per_run=5",
            csrf(&a)
        )
    };
    assert_eq!(post(&a, "/settings/safety", &form("5")).status, 303);
    let c = Config::load(&e.cfg_path).unwrap();
    assert_eq!(c.policy.prehire_days, 30);
    assert_eq!(c.policy.min_records, 5);
    // Which sign-in domains may exist is fixed in the config file: the GUI cannot add one.
    assert_eq!(c.policy.allowed_upn_domains, vec!["contoso.nl"]);
    // Only differences from the base are in the GUI layer.
    let ov = std::fs::read_to_string(e.state("overrides.toml")).unwrap();
    assert!(
        ov.contains("prehire_days = 30") && !ov.contains("max_drop_percent"),
        "{ov}"
    );
    let page = get(&a, "/settings/safety").text();
    assert!(page.contains("changed in GUI"));
    let audit = std::fs::read_to_string(e.state("audit.log")).unwrap();
    assert!(audit.contains("policy.prehire_days") && audit.contains("\"user\":\"local\""));
    // Invalid (out of range) is refused and not saved.
    let r = post(&a, "/settings/safety", &form("0"));
    assert_eq!(r.status, 400);
    assert!(r.text().contains("Not saved"));
    assert_eq!(Config::load(&e.cfg_path).unwrap().policy.min_records, 5);
    // Reset.
    assert_eq!(post(&a, "/settings/reset/safety", &csrf(&a)).status, 303);
    assert_eq!(Config::load(&e.cfg_path).unwrap().policy.prehire_days, 14);
    assert!(
        !e.state("overrides.toml").exists(),
        "empty GUI layer is cleaned up"
    );
    // Base file never touched.
    assert!(
        std::fs::read_to_string(&e.cfg_path)
            .unwrap()
            .contains("prehire_days = 14")
    );
}

#[test]
fn cross_field_validation_runs_before_saving() {
    let e = env("http://127.0.0.1:1");
    let a = app(&e, false, None);
    // backoff_max < backoff_base is invalid in Config::validate.
    let body = format!(
        "{}&upload.batch_size=50&upload.pace_ms=125&upload.max_attempts=4&upload.backoff_base_ms=9000&upload.backoff_max_ms=1000&upload.bucket_full_wait_secs=300&upload.max_retry_after_secs=120",
        csrf(&a)
    );
    let r = post(&a, "/settings/upload", &body);
    assert_eq!(r.status, 400, "{}", r.text());
    assert!(!e.state("overrides.toml").exists());
}

#[test]
fn toggles_can_be_switched_and_new_attributes_added() {
    let e = env("http://127.0.0.1:1");
    let a = app(&e, false, None);
    let body = format!(
        "{}&afas.fields.extra.phone_work.field=TelWerk&afas.fields.extra.office.enabled=on&afas.fields.extra.office.field=Standplaats&afas.fields.extra.city.enabled=on&afas.fields.extra.city.field=PlaatsWerk&afas.fields.extra.send_hire_date=on",
        csrf(&a)
    );
    assert_eq!(post(&a, "/settings/attributes", &body).status, 303);
    let x = Config::load(&e.cfg_path).unwrap().afas.fields.extra;
    assert!(!x.phone_work.unwrap().enabled);
    assert!(x.office.unwrap().enabled);
    assert_eq!(x.city.unwrap().field, "PlaatsWerk");
    assert!(x.send_hire_date);
    // On without a field name: refused.
    let r = post(
        &a,
        "/settings/attributes",
        &format!("{}&afas.fields.extra.street.enabled=on", csrf(&a)),
    );
    assert_eq!(r.status, 400);
    // Field name already in use: refused by config validation.
    let r = post(
        &a,
        "/settings/attributes",
        &format!(
            "{}&afas.fields.extra.phone_work.field=TelWerk&afas.fields.extra.office.field=Standplaats&afas.fields.extra.city.field=PlaatsWerk&afas.fields.extra.street.enabled=on&afas.fields.extra.street.field=Afdeling",
            csrf(&a)
        ),
    );
    assert_eq!(r.status, 400, "{}", r.text());
}

#[test]
fn clearing_a_configured_value_is_refused() {
    let e = env("http://127.0.0.1:1");
    let a = app(&e, false, None);
    let r = post(
        &a,
        "/settings/population",
        &format!(
            "{}&population.name=inhuur&population.id_prefix=INH-",
            csrf(&a)
        ),
    );
    assert_eq!(r.status, 303);
    let c = Config::load(&e.cfg_path).unwrap();
    assert_eq!(c.population.id_prefix.as_deref(), Some("INH-"));
    assert_eq!(
        c.afas.fields.population.id_prefix.as_deref(),
        Some("INH-"),
        "prefix also works in the parser"
    );
    // Invalid prefix.
    let r = post(
        &a,
        "/settings/population",
        &format!("{}&population.id_prefix=inh", csrf(&a)),
    );
    assert_eq!(r.status, 400);
    // Clearing a base value is not possible through the GUI.
    let r = post(
        &a,
        "/settings/fields",
        &format!("{}&afas.fields.employee_id=", csrf(&a)),
    );
    assert_eq!(r.status, 400);
}

// ------------------------------------------------------------------ runs

fn afas_with_rows() -> mockito::ServerGuard {
    let mut afas = mockito::Server::new();
    let mut rows: Vec<_> = (1..=3)
        .map(|i| row(&i.to_string(), d("2020-01-01"), None))
        .collect();
    for r in &mut rows {
        r.insert("TelWerk".into(), serde_json::json!("0301234567"));
    }
    afas.mock("GET", mockito::Matcher::Any)
        .with_body(afas_body(&rows))
        .create();
    afas
}

#[test]
fn dry_run_with_payload_download_and_delete() {
    let afas = afas_with_rows();
    let e = env(&afas.url());
    let a = app(&e, false, None);
    assert_eq!(
        post(&a, "/run/dry", &format!("{}&payload=on", csrf(&a))).status,
        303
    );
    let run = get(&a, "/run").text();
    assert!(
        run.contains("Succeeded") && run.contains("exit code 0"),
        "{run}"
    );
    let p = get(&a, "/payload");
    assert_eq!(p.status, 200);
    assert!(p.disposition.as_deref().unwrap().contains("attachment"));
    assert!(p.text().contains("\"externalId\""));
    assert_eq!(post(&a, "/payload/delete", &csrf(&a)).status, 303);
    assert_eq!(get(&a, "/payload").status, 404);
    let overview = get(&a, "/").text();
    assert!(
        overview.contains("Succeeded") && overview.contains("AFAS rows"),
        "{overview}"
    );
    let audit = std::fs::read_to_string(e.state("audit.log")).unwrap();
    for w in ["test run", "payload downloaded", "payload deleted"] {
        assert!(audit.contains(w), "{w}");
    }
    assert!(!e.state("state.json").exists(), "dry-run writes no state");
}

#[test]
fn dry_run_as_of_and_bad_date() {
    let afas = afas_with_rows();
    let e = env(&afas.url());
    let a = app(&e, false, None);
    let r = post(&a, "/run/dry", &format!("{}&as_of=31-12-2030", csrf(&a)));
    assert_eq!(r.location.as_deref(), Some("/run?m=date"));
    assert!(get(&a, "/run?m=date").text().contains("YYYY-MM-DD"));
    post(&a, "/run/dry", &format!("{}&as_of=2030-12-31", csrf(&a)));
    let rep: serde_json::Value =
        serde_json::from_slice(&std::fs::read(e.state("last-dry-run-report.json")).unwrap())
            .unwrap();
    assert_eq!(rep["today"], "2030-12-31");
}

#[test]
fn apply_requires_exact_confirmation() {
    let afas = afas_with_rows();
    let mut entra = mockito::Server::new();
    let tok = entra
        .mock("POST", mockito::Matcher::Regex("token".into()))
        .with_body(r#"{"access_token":"tok1","expires_in":3600}"#)
        .create();
    let up = entra
        .mock("POST", mockito::Matcher::Regex("bulkUpload".into()))
        .with_status(202)
        .expect(1)
        .create();
    let e = env_with(&afas.url(), &entra.url(), &format!("{EXTRA}{GUI_ON}"));
    let a = app(&e, false, None);
    // Without or with the wrong confirmation: nothing.
    assert_eq!(post(&a, "/run/apply", &csrf(&a)).status, 400);
    assert_eq!(
        post(&a, "/run/apply", &format!("{}&confirm=uitvoeren", csrf(&a))).status,
        400
    );
    // Mass disable asks for the other phrase.
    assert_eq!(
        post(
            &a,
            "/run/apply",
            &format!("{}&allow_mass_disable=on&confirm={CONFIRM_APPLY}", csrf(&a))
        )
        .status,
        400
    );
    let _ = CONFIRM_MASS;
    // Correct.
    assert_eq!(
        post(
            &a,
            "/run/apply",
            &format!("{}&confirm={CONFIRM_APPLY}", csrf(&a))
        )
        .status,
        303
    );
    up.assert();
    tok.assert();
    assert!(e.state("state.json").exists());
    assert!(
        std::fs::read_to_string(e.state("audit.log"))
            .unwrap()
            .contains("\"action\":\"sync\"")
    );
}

#[test]
fn check_config_and_check_logs() {
    let mut entra = mockito::Server::new();
    entra
        .mock("POST", mockito::Matcher::Regex("token".into()))
        .with_body(r#"{"access_token":"tok1","expires_in":3600}"#)
        .create();
    entra.mock("GET", mockito::Matcher::Regex("auditLogs".into()))
        .with_body(r#"{"value":[{"provisioningStatusInfo":{"status":"failure","errorInformation":{"reason":"UPN already exists"}},"sourceIdentity":{"id":"7"},"provisioningAction":"create"}]}"#)
        .create();
    let e = env_with(
        "http://127.0.0.1:1",
        &entra.url(),
        &format!("{EXTRA}{GUI_ON}"),
    );
    let a = app(&e, false, None);
    post(&a, "/run/check-config", &csrf(&a));
    assert!(get(&a, "/run").text().contains("Configuration OK"));
    post(&a, "/run/check-logs", &format!("{}&minutes=30", csrf(&a)));
    let page = get(&a, "/run").text();
    assert!(
        page.contains("1 failed")
            && page.contains("UPN already exists")
            && page.contains("exit code 50"),
        "{page}"
    );
    assert_eq!(
        post(&a, "/run/check-logs", &format!("{}&minutes=0", csrf(&a)))
            .location
            .as_deref(),
        Some("/run?m=minutes")
    );
}

#[test]
fn second_run_while_busy_is_refused() {
    let e = env("http://127.0.0.1:1");
    let a = app(&e, false, None);
    a.runs.lock().unwrap().current = Some(afas_entra_sync::web::RunInfo {
        kind: "sync".into(),
        user: "x".into(),
        started: "2026-10-31T10:00:00Z".into(),
    });
    let r = post(&a, "/run/dry", &csrf(&a));
    assert_eq!(r.location.as_deref(), Some("/run?m=busy"));
    assert!(get(&a, "/run").text().contains("Sync running"));
}

// ------------------------------------------------------------------ escaping

#[test]
fn output_is_escaped() {
    assert_eq!(esc("<script>'&\""), "&lt;script&gt;&#39;&amp;&quot;");
    let e = env("http://127.0.0.1:1");
    let rep = serde_json::json!({"mode":"dry-run","started_utc":"x","today":"<i>","result":"<b>bad</b>","exit_code":3,
        "counts":{"rows_fetched":1},"exclusions":[{"employee_id":"<img src=x>","reason":"r"}],"warnings":[],"violations":[],
        "disappeared_while_active":["<svg>"]});
    std::fs::write(e.state("last-report.json"), rep.to_string()).unwrap();
    std::fs::write(
        e.state("audit.log"),
        "{\"utc\":\"x\",\"user\":\"<script>\",\"action\":\"a\",\"detail\":\"d\"}\n",
    )
    .unwrap();
    let a = app(&e, false, None);
    let body = get(&a, "/").text() + &get(&a, "/audit").text();
    for bad in ["<img src=x>", "<b>bad</b>", "<svg>", "<script>", "<i>"] {
        assert!(!body.contains(bad), "{bad}");
    }
}

#[test]
fn form_parsing() {
    let f = parse_form(b"a=1&b=hallo+wereld&c=%3Cx%3E&d&e=%zz&f=%4");
    let g = |k: &str| f.iter().find(|(a, _)| a == k).map(|(_, v)| v.as_str());
    assert_eq!(g("a"), Some("1"));
    assert_eq!(g("b"), Some("hallo wereld"));
    assert_eq!(g("c"), Some("<x>"));
    assert_eq!(g("d"), Some(""));
    assert_eq!(g("e"), Some("%zz"));
    assert_eq!(g("f"), Some("%4"));
}

// ------------------------------------------------------------------ local sign-in

fn raw(a: &App, path: &str, headers: &[(String, String)]) -> Response {
    handle(
        a,
        &Request {
            method: "GET",
            path,
            remote: Some("127.0.0.1".parse().unwrap()),
            headers,
            body: b"",
        },
    )
}

#[test]
fn local_mode_requires_login_link_and_session_cookie() {
    let e = env("http://127.0.0.1:1");
    let a = app(&e, false, None);
    let host = ("host".to_string(), "127.0.0.1:8080".to_string());
    // No cookie: refused, and no CSRF token leaks.
    let r = raw(&a, "/", std::slice::from_ref(&host));
    assert_eq!(r.status, 401);
    assert!(!r.text().contains(&a.csrf));
    // Wrong cookie, wrong token: refused.
    let bad = vec![
        host.clone(),
        ("cookie".into(), format!("{SESSION_COOKIE}=00")),
    ];
    assert_eq!(raw(&a, "/", &bad).status, 401);
    assert_eq!(
        raw(&a, "/login?token=abc", std::slice::from_ref(&host)).status,
        403
    );
    assert_eq!(raw(&a, "/login", std::slice::from_ref(&host)).status, 403);
    // Correct login link: a new session, cookie __Host-, Secure, HttpOnly, SameSite=Strict.
    let link = a.login_token();
    let r = raw(
        &a,
        &format!("/login?token={link}"),
        std::slice::from_ref(&host),
    );
    assert_eq!(r.status, 303);
    let c = r.set_cookie.unwrap();
    assert!(c.starts_with(&format!("{SESSION_COOKIE}=")), "{c}");
    for attr in ["Secure", "HttpOnly", "SameSite=Strict", "Path=/"] {
        assert!(c.contains(attr), "{attr}: {c}");
    }
    assert!(!c.contains(&link) && !c.contains("Domain"));
    assert_eq!(a.session_count(), 1);
    // The link works once; a fresh one replaces it.
    let again = raw(
        &a,
        &format!("/login?token={link}"),
        std::slice::from_ref(&host),
    );
    assert_eq!(again.status, 403);
    assert_ne!(a.login_token(), link);
    // POST without a session is refused before CSRF is even checked.
    let r = handle(
        &a,
        &Request {
            method: "POST",
            path: "/gui/off",
            remote: None,
            headers: std::slice::from_ref(&host),
            body: csrf(&a).as_bytes(),
        },
    );
    assert_eq!(r.status, 401);
    assert!(!a.shutdown.load(Ordering::SeqCst));
    // Health stays open for monitoring.
    assert_eq!(raw(&a, "/health", &[]).status, 200);
}

#[test]
fn local_mode_refuses_foreign_host_header() {
    let e = env("http://127.0.0.1:1");
    let a = app(&e, false, None);
    let cookie = (
        "cookie".to_string(),
        format!("{SESSION_COOKIE}={}", a.new_session().unwrap()),
    );
    for h in ["evil.example", "127.0.0.1:9999", "attacker.test:8080"] {
        let r = raw(&a, "/", &[("host".into(), h.into()), cookie.clone()]);
        assert_eq!(r.status, 421, "{h}");
    }
    assert_eq!(raw(&a, "/", std::slice::from_ref(&cookie)).status, 421);
    for h in ["localhost:8080", "LOCALHOST:8080", "127.0.0.1:8080"] {
        let r = raw(&a, "/", &[("host".into(), h.into()), cookie.clone()]);
        assert_eq!(r.status, 200, "{h}");
    }
}

#[test]
fn secrets_are_random_and_compared_safely() {
    use afas_entra_sync::web::ct_eq;
    let e = env("http://127.0.0.1:1");
    let a = app(&e, false, None);
    let b = app(&e, false, None);
    let (s1, s2) = (a.new_session().unwrap(), a.new_session().unwrap());
    for s in [&a.csrf, &a.login_token(), &s1, &s2] {
        assert_eq!(s.len(), 64);
        assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
    }
    assert_ne!(s1, s2, "every sign-in gets its own session");
    assert_ne!(a.login_token(), b.login_token());
    assert!(ct_eq("abc", "abc"));
    assert!(!ct_eq("abc", "abd") && !ct_eq("abc", "ab") && !ct_eq("", "a"));
}

#[test]
fn tls_settings_are_shown_locked_and_cannot_be_changed() {
    let e = env_with(
        "http://127.0.0.1:1",
        "http://127.0.0.1:1",
        &format!("{EXTRA}{GUI_ON}\n[tls]\nmin_version = \"1.3\"\npost_quantum = \"prefer\"\n"),
    );
    let a = app(&e, false, None);
    let page = get(&a, "/settings/tls").text();
    assert!(page.contains("Minimum TLS version") && page.contains("fixed in config file"));
    assert!(page.contains("name=\"tls.min_version\" value=\"1.3\" disabled"));
    let r = post(
        &a,
        "/settings/tls",
        &format!("{}&tls.min_version=1.2&tls.post_quantum=prefer", csrf(&a)),
    );
    assert_eq!(r.status, 303);
    assert!(
        !e.state("overrides.toml").exists(),
        "locked: nothing written"
    );
    assert!(get(&a, "/run").text().contains("Check TLS"));
    std::fs::write(e.state("overrides.toml"), "[tls]\nmin_version = \"1.2\"\n").unwrap();
    assert!(
        Config::load(&e.cfg_path).is_err(),
        "hand-written TLS override refused"
    );
}

// ------------------------------------------------------------------ modules

const GRP: &str = "a1a1a1a1-0000-0000-0000-000000000001";

fn roles_toml(dir: &std::path::Path) -> String {
    format!(
        "\n[roles]\nenabled = false\nclient_id = \"c0000000-0000-0000-0000-000000000001\"\ncertificate_pem = \"{}\"\nprivate_key_pem = \"{}\"\ngroup_prefix = \"AFAS-\"\n[[roles.rule]]\ngroup_id = \"{GRP}\"\nname = \"AFAS-ICT\"\ndepartment = [\"ICT\"]\n",
        fixture("test-cert.pem"),
        dir.join("test-key.pem").display()
    )
}

#[test]
fn module_pages_without_setup_show_how_and_refuse_saving() {
    let e = env("http://127.0.0.1:1");
    let a = app(&e, false, None);
    let page = get(&a, "/settings/roles").text();
    assert!(
        page.contains("Not set up") && page.contains("[roles]"),
        "{page}"
    );
    assert!(!page.contains("Save changes"));
    let r = post(
        &a,
        "/settings/roles",
        &format!("{}&roles.enabled=on", csrf(&a)),
    );
    assert_eq!(r.status, 409);
    assert!(!e.state("overrides.toml").exists());
    for p in [
        "/modules",
        "/access",
        "/exceptions",
        "/settings/joiner",
        "/settings/leaver",
    ] {
        assert_eq!(get(&a, p).status, 200, "{p}");
    }
}

#[test]
fn roles_settings_exceptions_and_access_export() {
    let e0 = env("http://127.0.0.1:1");
    // Reuse the env's directory layout: the key copy lives next to afas.token.
    let toml =
        std::fs::read_to_string(&e0.cfg_path).unwrap() + &roles_toml(e0.cfg_path.parent().unwrap());
    std::fs::write(&e0.cfg_path, toml).unwrap();
    let e = e0;
    let a = app(&e, false, None);
    // Modules page lists the rule.
    let m = get(&a, "/modules").text();
    assert!(
        m.contains("AFAS-ICT") && m.contains("department: ICT"),
        "{m}"
    );
    // Settings: switch the module on through the GUI layer.
    let r = post(
        &a,
        "/settings/roles",
        &format!(
            "{}&roles.enabled=on&roles.keep_leavers_days=20&roles.max_changes_per_run=25",
            csrf(&a)
        ),
    );
    assert_eq!(r.status, 303, "{}", r.text());
    let c = Config::load(&e.cfg_path).unwrap();
    let rc = c.roles.unwrap();
    assert!(rc.enabled && rc.keep_leavers_days == 20 && rc.max_changes_per_run == 25);
    // Exceptions: unknown group refused, rule group accepted, then removed.
    let until = (chrono::Utc::now().date_naive() + chrono::Days::new(10)).to_string();
    let bad = post(
        &a,
        "/exceptions/add",
        &format!(
            "{}&employee=00001&group=a1a1a1a1-0000-0000-0000-00000000ffff&kind=include&until={until}&reason=x",
            csrf(&a)
        ),
    );
    assert_eq!(bad.status, 400);
    assert!(bad.text().contains("not in the role rules"));
    let ok = post(
        &a,
        "/exceptions/add",
        &format!(
            "{}&employee=00001&group={GRP}&kind=exclude&until={until}&reason=Project+X",
            csrf(&a)
        ),
    );
    assert_eq!(ok.status, 303);
    let page = get(&a, "/exceptions").text();
    assert!(page.contains("Project X") && page.contains("keep out"));
    let x = afas_entra_sync::modules::records::load_exceptions(&e.state("")).unwrap();
    assert_eq!(x.items.len(), 1);
    assert_eq!(x.items[0].created_by, "local");
    let r = post(
        &a,
        "/exceptions/remove",
        &format!("{}&id={}", csrf(&a), x.items[0].id),
    );
    assert_eq!(r.status, 303);
    assert!(
        afas_entra_sync::modules::records::load_exceptions(&e.state(""))
            .unwrap()
            .items
            .is_empty()
    );
    // Access log export is a CSV download and is audited.
    afas_entra_sync::modules::records::append_access(
        &e.state(""),
        &afas_entra_sync::modules::records::AccessEntry {
            utc: "2026-11-01T10:00:00Z".into(),
            module: "roles".into(),
            action: "add_to_group".into(),
            employee_id: Some("00001".into()),
            upn: Some("a@b.nl".into()),
            target: Some("AFAS-ICT".into()),
            ok: true,
            detail: None,
            actor: "test".into(),
        },
    )
    .unwrap();
    assert!(
        get(&a, "/access?employee=00001")
            .text()
            .contains("added to group")
    );
    assert!(
        !get(&a, "/access?employee=99999")
            .text()
            .contains("add to group")
    );
    let csv = get(&a, "/access.csv?employee=00001");
    assert_eq!(csv.content_type, "text/csv; charset=utf-8");
    assert!(csv.text().starts_with("utc,module,action"));
    let audit = std::fs::read_to_string(e.state("audit.log")).unwrap();
    for w in [
        "exception added",
        "exception removed",
        "access log exported",
    ] {
        assert!(audit.contains(w), "{w}");
    }
}

/// Keys left out of the config file show their default, and saving the page unchanged
/// changes nothing (before 0.9.1 an absent `revoke_sessions = true` showed as off and was
/// saved as false).
#[test]
fn module_settings_show_defaults_and_saving_unchanged_keeps_them() {
    let e = env("http://127.0.0.1:1");
    let dir = e.cfg_path.parent().unwrap().to_path_buf();
    let toml = std::fs::read_to_string(&e.cfg_path).unwrap()
        + &format!(
            "\n[leaver]\nenabled = true\nclient_id = \"c0000000-0000-0000-0000-000000000002\"\ncertificate_pem = \"{}\"\nprivate_key_pem = \"{}\"\nauto_reply = \"Gone\"\n",
            fixture("test-cert.pem"),
            dir.join("test-key.pem").display()
        );
    std::fs::write(&e.cfg_path, toml).unwrap();
    let a = app(&e, false, None);
    let page = get(&a, "/settings/leaver").text();
    assert!(
        page.contains("name=\"leaver.revoke_sessions\" checked"),
        "{page}"
    );
    assert!(
        page.contains("name=\"leaver.grace_days\" value=\"7\""),
        "{page}"
    );
    assert!(
        page.contains("name=\"leaver.max_per_run\" value=\"10\""),
        "{page}"
    );
    assert!(page.contains("Departing employees (leavers)"));
    // Save exactly what the page shows: nothing changes, no override is written.
    let same = format!(
        "{}&leaver.enabled=on&leaver.revoke_sessions=on&leaver.auto_reply=Gone&leaver.grace_days=7&leaver.max_per_run=10",
        csrf(&a)
    );
    let r = post(&a, "/settings/leaver", &same);
    assert_eq!(r.status, 303, "{}", r.text());
    assert!(!e.state("overrides.toml").exists());
    assert!(
        Config::load(&e.cfg_path)
            .unwrap()
            .leaver
            .unwrap()
            .revoke_sessions
    );
    // Unticking it is a real, saved change.
    let off = format!(
        "{}&leaver.enabled=on&leaver.auto_reply=Gone&leaver.grace_days=7&leaver.max_per_run=10",
        csrf(&a)
    );
    assert_eq!(post(&a, "/settings/leaver", &off).status, 303);
    let ov = std::fs::read_to_string(e.state("overrides.toml")).unwrap();
    assert!(
        ov.contains("revoke_sessions = false") && !ov.contains("grace_days"),
        "{ov}"
    );
    assert!(
        !Config::load(&e.cfg_path)
            .unwrap()
            .leaver
            .unwrap()
            .revoke_sessions
    );
}

// ------------------------------------------------------------------ sessions (ASVS V7)

fn with_session(id: &str) -> Vec<(String, String)> {
    vec![
        ("host".into(), "127.0.0.1:8080".into()),
        ("cookie".into(), format!("{SESSION_COOKIE}={id}")),
    ]
}

fn post_as(a: &App, id: &str, path: &str, body: &str) -> Response {
    handle(
        a,
        &Request {
            method: "POST",
            path,
            remote: Some("127.0.0.1".parse().unwrap()),
            headers: &with_session(id),
            body: body.as_bytes(),
        },
    )
}

#[test]
fn sessions_end_after_inactivity_and_after_their_maximum_lifetime() {
    let e = env("http://127.0.0.1:1");
    let mut a = app(&e, false, None);
    let id = a.new_session().unwrap();
    assert_eq!(raw(&a, "/", &with_session(&id)).status, 200);
    // Inactivity.
    a.idle_timeout = std::time::Duration::ZERO;
    assert_eq!(raw(&a, "/", &with_session(&id)).status, 401);
    // Ended means gone: restoring the timeout does not bring it back.
    a.idle_timeout = afas_entra_sync::web::IDLE_TIMEOUT;
    assert_eq!(raw(&a, "/", &with_session(&id)).status, 401);
    // Maximum lifetime, even when active.
    let id = a.new_session().unwrap();
    a.max_lifetime = std::time::Duration::ZERO;
    assert_eq!(raw(&a, "/", &with_session(&id)).status, 401);
    let audit = std::fs::read_to_string(e.state("audit.log")).unwrap();
    assert!(audit.contains("session expired"), "{audit}");
}

#[test]
fn login_link_expires_and_wrong_tokens_are_logged() {
    let e = env("http://127.0.0.1:1");
    let mut a = app(&e, false, None);
    let host = [("host".to_string(), "127.0.0.1:8080".to_string())];
    // Wrong token: refused, the real link stays valid.
    let link = a.login_token();
    assert_eq!(raw(&a, "/login?token=00", &host).status, 403);
    assert_eq!(a.login_token(), link);
    // Expired link: refused and replaced.
    a.login_ttl = std::time::Duration::ZERO;
    assert_eq!(raw(&a, &format!("/login?token={link}"), &host).status, 403);
    assert_ne!(a.login_token(), link);
    // Successful sign-in is logged with where it came from.
    a.login_ttl = afas_entra_sync::web::LOGIN_TTL;
    let ok = raw(&a, &format!("/login?token={}", a.login_token()), &host);
    assert_eq!(ok.status, 303);
    let audit = std::fs::read_to_string(e.state("audit.log")).unwrap();
    assert_eq!(audit.matches("\"login refused\"").count(), 2, "{audit}");
    assert!(audit.contains("wrong token") && audit.contains("expired or already used"));
    assert!(audit.contains("\"action\":\"login\"") && audit.contains("from 127.0.0.1"));
}

#[test]
fn sign_out_ends_the_session_also_in_read_only_mode() {
    let e = env("http://127.0.0.1:1");
    for ro in [false, true] {
        let a = app(&e, ro, None);
        let id = a.new_session().unwrap();
        let page = raw(&a, "/", &with_session(&id)).text();
        assert!(page.contains("action=/logout"), "sign-out button");
        // Without the form token: refused.
        assert_eq!(post_as(&a, &id, "/logout", "").status, 403);
        assert_eq!(raw(&a, "/", &with_session(&id)).status, 200);
        let r = post_as(&a, &id, "/logout", &format!("csrf={}", a.csrf));
        assert_eq!(r.status, 200, "read_only={ro}");
        assert!(r.set_cookie.unwrap().contains("Max-Age=0"));
        assert_eq!(raw(&a, "/", &with_session(&id)).status, 401);
        assert_eq!(a.session_count(), 0);
    }
    let audit = std::fs::read_to_string(e.state("audit.log")).unwrap();
    assert_eq!(audit.matches("\"logout\"").count(), 2);
}

#[test]
fn sessions_are_capped_and_the_oldest_ends_first() {
    let e = env("http://127.0.0.1:1");
    let a = app(&e, false, None);
    let first = a.new_session().unwrap();
    for _ in 1..MAX_SESSIONS {
        a.new_session().unwrap();
    }
    assert_eq!(a.session_count(), MAX_SESSIONS);
    let newest = a.new_session().unwrap();
    assert_eq!(a.session_count(), MAX_SESSIONS);
    assert_eq!(raw(&a, "/", &with_session(&first)).status, 401);
    assert_eq!(raw(&a, "/", &with_session(&newest)).status, 200);
}

#[test]
fn proxy_mode_has_no_local_sign_out() {
    let e = env("http://127.0.0.1:1");
    let proxy: IpAddr = "10.0.0.5".parse().unwrap();
    let a = app(&e, false, Some(proxy));
    let r = handle(
        &a,
        &Request {
            method: "GET",
            path: "/",
            remote: Some(proxy),
            headers: &[("x-authentik-username".into(), "ward".into())],
            body: b"",
        },
    );
    assert_eq!(r.status, 200);
    assert!(!r.text().contains("action=/logout"));
}

#[test]
fn all_sessions_can_be_ended_and_refused_form_tokens_are_logged() {
    let e = env("http://127.0.0.1:1");
    let a = app(&e, false, None);
    let mine = a.new_session().unwrap();
    let other = a.new_session().unwrap();
    let page = raw(&a, "/gui", &with_session(&mine)).text();
    assert!(
        page.contains("2 active") && page.contains("Sign out all sessions"),
        "{page}"
    );
    // A POST with a wrong form token is refused and logged.
    assert_eq!(
        post_as(&a, &mine, "/settings/safety", "csrf=nope").status,
        403
    );
    let r = post_as(&a, &mine, "/logout", &format!("csrf={}&all=1", a.csrf));
    assert_eq!(r.status, 200);
    for id in [&mine, &other] {
        assert_eq!(raw(&a, "/", &with_session(id)).status, 401);
    }
    let audit = std::fs::read_to_string(e.state("audit.log")).unwrap();
    assert!(
        audit.contains("\"form token refused\"") && audit.contains("all sessions"),
        "{audit}"
    );
}

#[test]
fn only_get_and_post_are_answered() {
    let e = env("http://127.0.0.1:1");
    let a = app(&e, false, None);
    let id = a.new_session().unwrap();
    for m in ["PUT", "DELETE", "TRACE", "OPTIONS", "PATCH"] {
        let r = handle(
            &a,
            &Request {
                method: m,
                path: "/",
                remote: Some("127.0.0.1".parse().unwrap()),
                headers: &with_session(&id),
                body: b"",
            },
        );
        assert_eq!(r.status, 405, "{m}");
    }
}

#[test]
fn request_body_limit_is_exactly_64_kib() {
    let e = env("http://127.0.0.1:1");
    let a = app(&e, false, None);
    let id = a.new_session().unwrap();
    let base = format!("csrf={}&x=", a.csrf);
    let at_limit = base.clone() + &"a".repeat(64 * 1024 - base.len());
    assert_eq!(at_limit.len(), 64 * 1024);
    // At the limit the request is read (and then refused for its content, not its size).
    assert_ne!(post_as(&a, &id, "/settings/safety", &at_limit).status, 413);
    let over = at_limit + "a";
    assert_eq!(post_as(&a, &id, "/settings/safety", &over).status, 413);
}

#[test]
fn health_check_runs_from_the_gui_and_shows_fixes() {
    let afas = afas_with_rows();
    let mut entra = mockito::Server::new();
    entra
        .mock("POST", mockito::Matcher::Regex("token".into()))
        .with_body(r#"{"access_token":"tok1","expires_in":3600}"#)
        .create();
    entra
        .mock("GET", mockito::Matcher::Regex("auditLogs".into()))
        .with_status(403)
        .with_body(r#"{"error":{"code":"Authorization_RequestDenied","message":"Insufficient privileges"}}"#)
        .create();
    let e = env_with(&afas.url(), &entra.url(), &format!("{EXTRA}{GUI_ON}"));
    let a = app(&e, false, None);
    assert!(get(&a, "/run").text().contains("Run health check"));
    post(&a, "/run/doctor", &csrf(&a));
    let page = get(&a, "/run").text();
    assert!(page.contains("GetConnector"), "{page}");
    assert!(page.contains("Grant admin consent"), "{page}");
    assert!(page.contains("exit code 61"), "{page}");
    assert!(
        page.contains("1 problem to fix") && page.contains("<li class=fail>"),
        "{page}"
    );
    assert!(page.contains("What to do: grant the application permission ProvisioningLog.Read.All"));
}

// ------------------------------------------------------------------ preview, missing, overrides (0.11)

#[test]
fn preview_page_shows_the_last_test_run_and_downloads_are_audited() {
    let e = env("http://127.0.0.1:1");
    let a = app(&e, false, None);
    let empty = get(&a, "/preview").text();
    assert!(empty.contains("No test run yet") && empty.contains("Go to Run"));
    assert_eq!(get(&a, "/preview.csv").status, 404);
    let demo = afas_entra_sync::preview::demo();
    std::fs::write(
        e.state("last-dry-run-preview.json"),
        serde_json::to_vec(&demo).unwrap(),
    )
    .unwrap();
    let page = get(&a, "/preview").text();
    for part in [
        "Microsoft would create 2 accounts",
        "Where the accounts are",
        "Call 1 of 4 to Microsoft",
        "Senior adviseur",
        "aria-current=page>Changes",
        "Download CSV",
    ] {
        assert!(page.contains(part), "missing {part}");
    }
    assert!(
        !page.contains("Colleague 10100"),
        "unchanged accounts are not in Changes"
    );
    let all = get(&a, "/preview?of=dry&show=upload").text();
    assert!(all.contains("Colleague 10100"));
    let problems = get(&a, "/preview?of=dry&show=problems").text();
    assert!(problems.contains("Link first") && !problems.contains("Senior adviseur"));
    // The last sync has its own tab.
    assert!(get(&a, "/preview?of=sync").text().contains("No sync yet"));
    let csv = get(&a, "/preview.csv?of=dry");
    assert_eq!(csv.status, 200);
    assert!(
        csv.disposition
            .as_deref()
            .unwrap()
            .contains("afas-entra-test-run-preview.csv")
    );
    assert!(csv.text().starts_with("call,action,employee_number"));
    let html = get(&a, "/preview.html?of=dry");
    assert!(html.text().starts_with("<!doctype html>"));
    let audit = std::fs::read_to_string(e.state("audit.log")).unwrap();
    assert!(audit.contains("preview downloaded") && audit.contains("test-run csv"));
    // In the menu.
    assert!(get(&a, "/").text().contains("href=/preview"));
}

#[test]
fn missing_employees_can_be_marked_handled_from_the_overview() {
    use afas_entra_sync::state::{RecordState, STATE_VERSION, State, StateStore};
    let e = env("http://127.0.0.1:1");
    let a = app(&e, false, None);
    let mut st = State {
        version: STATE_VERSION,
        last_success_utc: "2026-11-02T10:00:00Z".into(),
        sent_total: 0,
        records: Default::default(),
    };
    let mut gone = RecordState::new(true);
    gone.missing_since = Some(d("2026-10-30"));
    st.records.insert("00042".into(), gone);
    StateStore::new(&e.state("")).unwrap().save(&st).unwrap();
    let rep = serde_json::json!({
        "mode": "apply", "started_utc": "2026-11-03T10:07:00Z", "today": "2026-11-03",
        "counts": {}, "exit_code": 3, "result": "ok, but records need attention",
        "missing": [ { "employee_id": "00042", "since": "2026-10-30" } ],
        "manager_gaps": [ { "manager_id": "00007", "cause": "left", "date": "2026-10-01", "reports": ["00011", "00012"] } ]
    });
    std::fs::write(e.state("last-report.json"), rep.to_string()).unwrap();
    let page = get(&a, "/").text();
    assert!(page.contains("Missing from AFAS while active (1)") && page.contains("2026-10-30"));
    assert!(page.contains("Mark handled"));
    assert!(
        page.contains("Managers who left or cannot be linked (1)") && page.contains("00011, 00012")
    );
    let r = post(&a, "/missing/ack", &format!("{}&employee=00042", csrf(&a)));
    assert_eq!(r.status, 303, "{}", r.text());
    let after = StateStore::new(&e.state(""))
        .unwrap()
        .load()
        .unwrap()
        .unwrap();
    assert!(!after.records.contains_key("00042"));
    assert!(
        std::fs::read_to_string(e.state("audit.log"))
            .unwrap()
            .contains("missing acknowledged")
    );
    // A number that is not missing.
    assert_eq!(
        post(&a, "/missing/ack", &format!("{}&employee=99999", csrf(&a))).status,
        409
    );
    // Without the form token: refused.
    assert_eq!(post(&a, "/missing/ack", "employee=00042").status, 403);
}

#[test]
fn a_newer_test_run_does_not_hide_the_last_sync() {
    let e = env("http://127.0.0.1:1");
    let a = app(&e, false, None);
    let sync = serde_json::json!({"mode": "apply", "started_utc": "2026-11-03T09:07:00+00:00", "today": "2026-11-03", "counts": {}, "exit_code": 41, "result": "upload error: HTTP 500"});
    let dry = serde_json::json!({"mode": "dry-run", "started_utc": "2026-11-03T10:30:00+00:00", "today": "2026-11-03", "counts": {}, "exit_code": 0, "result": "ok"});
    std::fs::write(e.state("last-report.json"), sync.to_string()).unwrap();
    std::fs::write(e.state("last-dry-run-report.json"), dry.to_string()).unwrap();
    let page = get(&a, "/").text();
    assert!(
        page.contains("upload error: HTTP 500"),
        "the failed sync stays visible"
    );
    assert!(page.contains("A newer test run"));
}

#[test]
fn every_threshold_override_needs_the_strong_confirmation() {
    let e = env("http://127.0.0.1:1");
    let a = app(&e, false, None);
    let page = get(&a, "/run").text();
    assert!(page.contains("name=allow_mass_create") && page.contains("name=allow_upn_changes"));
    for flag in ["allow_mass_create", "allow_upn_changes"] {
        let r = post(
            &a,
            "/run/apply",
            &format!("{}&{flag}=on&confirm={CONFIRM_APPLY}", csrf(&a)),
        );
        assert_eq!(r.status, 400, "{flag}");
        assert!(r.text().contains(CONFIRM_MASS));
    }
}

#[test]
fn notification_test_button_only_with_notify() {
    let e = env("http://127.0.0.1:1");
    let a = app(&e, false, None);
    assert!(!get(&a, "/run").text().contains("Send a test message"));
    let r = post(&a, "/notify/test", &csrf(&a));
    assert_eq!(r.status, 303);
    assert!(r.location.unwrap().contains("notnotify"));
}
