// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The afas-entra-sync Authors
//! Tests for the admin GUI through `web::handle` (without networking).

mod common;

use afas_entra_sync::config::{Config, check_overrides};
use afas_entra_sync::web::{
    App, CONFIRM_APPLY, CONFIRM_MASS, Request, Response, WebOptions, esc, handle, parse_form,
    validate_listen,
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
            format!("other=1; afas_gui_session={}", a.session),
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
            "{}&policy.timezone=Europe%2FAmsterdam&policy.allowed_upn_domains=contoso.nl%2C+example.com&policy.prehire_days=30&policy.leaver_lookback_days=30&policy.min_records={min}&policy.max_drop_percent=10&policy.max_disables_per_run=10&policy.max_invalid_percent=10&policy.max_calls_per_run=100",
            csrf(&a)
        )
    };
    assert_eq!(post(&a, "/settings/safety", &form("5")).status, 303);
    let c = Config::load(&e.cfg_path).unwrap();
    assert_eq!(c.policy.prehire_days, 30);
    assert_eq!(c.policy.min_records, 5);
    assert_eq!(
        c.policy.allowed_upn_domains,
        vec!["contoso.nl", "example.com"]
    );
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
        serde_json::from_slice(&std::fs::read(e.state("last-report.json")).unwrap()).unwrap();
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
        ("cookie".into(), "afas_gui_session=00".into()),
    ];
    assert_eq!(raw(&a, "/", &bad).status, 401);
    assert_eq!(
        raw(&a, "/login?token=abc", std::slice::from_ref(&host)).status,
        403
    );
    assert_eq!(raw(&a, "/login", std::slice::from_ref(&host)).status, 403);
    // Correct login link: session cookie, HttpOnly, SameSite=Strict.
    let r = raw(
        &a,
        &format!("/login?token={}", a.login_token),
        std::slice::from_ref(&host),
    );
    assert_eq!(r.status, 303);
    let c = r.set_cookie.unwrap();
    assert!(c.starts_with(&format!("afas_gui_session={};", a.session)));
    assert!(c.contains("HttpOnly") && c.contains("SameSite=Strict"));
    assert_ne!(a.session, a.login_token);
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
        format!("afas_gui_session={}", a.session),
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
    for s in [&a.csrf, &a.login_token, &a.session] {
        assert_eq!(s.len(), 64);
        assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
    }
    assert_ne!(a.session, b.session);
    assert_ne!(a.login_token, b.login_token);
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
            "{}&roles.enabled=on&roles.keep_leavers_days=30&roles.max_changes_per_run=25",
            csrf(&a)
        ),
    );
    assert_eq!(r.status, 303, "{}", r.text());
    let c = Config::load(&e.cfg_path).unwrap();
    let rc = c.roles.unwrap();
    assert!(rc.enabled && rc.keep_leavers_days == 30 && rc.max_changes_per_run == 25);
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
