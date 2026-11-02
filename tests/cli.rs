// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The afas-entra-sync Authors
//! Tests of the real program (main.rs): arguments, environment variables,
//! client secret authentication, exit codes and JSON output.

mod common;

use common::*;
use mockito::{Matcher, Server};
use serde_json::Value;
use std::process::Command;

fn bin() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_afas-entra-sync"));
    for v in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "http_proxy",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
    ] {
        c.env_remove(v);
    }
    c.env("NO_PROXY", "127.0.0.1,localhost");
    c
}

fn write_cfg(dir: &std::path::Path, afas: &str, entra: &str) -> std::path::PathBuf {
    let token = dir.join("unused.token");
    let toml = config_toml(
        afas,
        entra,
        &dir.join("state"),
        &token,
        "client_secret",
        &Opts::default(),
    )
    .replace(
        &format!("token_file = \"{}\"", token.display()),
        "token_env = \"TEST_AFAS_TOKEN\"",
    );
    let p = dir.join("cfg.toml");
    std::fs::write(&p, toml).unwrap();
    p
}

/// `serve --trusted-proxy` refuses to start without a usable proxy secret file. Every case
/// ends before the server would listen, so the test never blocks.
#[test]
fn serve_behind_a_proxy_needs_a_private_secret_file() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let p = write_cfg(dir.path(), "http://127.0.0.1:1", "http://127.0.0.1:1");
    std::fs::write(
        &p,
        std::fs::read_to_string(&p).unwrap() + "\n[gui]\nenabled = true\n",
    )
    .unwrap();
    let serve = |extra: &[&str]| {
        let mut args = vec![
            "-c",
            p.to_str().unwrap(),
            "serve",
            "--listen",
            "127.0.0.1:0",
            "--trusted-proxy",
            "127.0.0.1",
        ];
        args.extend_from_slice(extra);
        let out = bin()
            .args(&args)
            .env("TEST_AFAS_TOKEN", "x")
            .output()
            .unwrap();
        (
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    };
    let (code, err) = serve(&[]);
    assert_eq!(code, Some(10), "{err}");
    assert!(err.contains("--proxy-secret-file"), "{err}");

    let secret = dir.path().join("gui-proxy-secret");
    std::fs::write(&secret, "0123456789abcdef0123456789abcdef\n").unwrap(); // pragma: allowlist secret (test value)
    std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o644)).unwrap();
    let (code, err) = serve(&["--proxy-secret-file", secret.to_str().unwrap()]);
    assert_eq!(code, Some(10), "{err}");
    assert!(err.contains("accessible by group or others"), "{err}");

    std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(&secret, "too-short\n").unwrap();
    let (code, err) = serve(&["--proxy-secret-file", secret.to_str().unwrap()]);
    assert_eq!(code, Some(10), "{err}");
    assert!(err.contains("at least 32"), "{err}");

    let missing = dir.path().join("missing");
    let (code, _) = serve(&["--proxy-secret-file", missing.to_str().unwrap()]);
    assert_eq!(code, Some(10));
}

#[test]
fn check_config_ok_and_bad() {
    let dir = tempfile::tempdir().unwrap();
    let p = write_cfg(dir.path(), "http://127.0.0.1:1", "http://127.0.0.1:1");
    let out = bin()
        .args(["-c", p.to_str().unwrap(), "check-config"])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    std::fs::write(&p, "[afas]\nbase_url = 1").unwrap();
    let out = bin()
        .args(["-c", p.to_str().unwrap(), "check-config"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(10));

    let out = bin()
        .args(["-c", "/does/not/exist.toml", "check-config"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(10));
}

#[test]
fn missing_secret_env_is_config_error_before_anything_is_sent() {
    let mut afas = Server::new();
    let entra = Server::new();
    let m = afas.mock("GET", Matcher::Any).expect(0).create();
    let dir = tempfile::tempdir().unwrap();
    let p = write_cfg(dir.path(), &afas.url(), &entra.url());
    let out = bin()
        .args(["-c", p.to_str().unwrap(), "sync", "--apply"])
        .env("TEST_AFAS_TOKEN", "ABCDEF0123456789")
        .env_remove("TEST_ENTRA_SECRET")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(10));
    m.assert();
}

#[test]
fn full_apply_with_client_secret_via_cli() {
    let mut afas = Server::new();
    let mut entra = Server::new();
    let start = today_ams()
        .checked_sub_days(chrono::Days::new(100))
        .unwrap();
    let rows: Vec<_> = (1..=3).map(|i| row(&i.to_string(), start, None)).collect();
    afas.mock("GET", "/ProfitRestServices/connectors/Entra_Medewerkers")
        .match_query(Matcher::Any)
        .with_body(afas_body(&rows))
        .create();
    let tok = entra
        .mock("POST", format!("/{TENANT}/oauth2/v2.0/token").as_str())
        .match_body(Matcher::AllOf(vec![
            Matcher::UrlEncoded("client_secret".into(), "geheim~1".into()),
            Matcher::UrlEncoded("grant_type".into(), "client_credentials".into()),
        ]))
        .with_body(r#"{"access_token":"tok1","expires_in":3600}"#)
        .expect(1)
        .create();
    let up = entra
        .mock(
            "POST",
            format!("/v1.0/servicePrincipals/{SP}/synchronization/jobs/{JOB}/bulkUpload").as_str(),
        )
        .match_header("authorization", "Bearer tok1")
        .with_status(202)
        .expect(1)
        .create();
    let dir = tempfile::tempdir().unwrap();
    let p = write_cfg(dir.path(), &afas.url(), &entra.url());
    let out = bin()
        .args(["-c", p.to_str().unwrap(), "sync", "--apply"])
        .env("TEST_AFAS_TOKEN", "ABCDEF0123456789")
        .env("TEST_ENTRA_SECRET", "geheim~1")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    assert!(
        !stderr.contains("geheim~1") && !String::from_utf8_lossy(&out.stdout).contains("geheim~1"),
        "secret leaked"
    );
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["mode"], "apply");
    assert_eq!(report["counts"]["sent_total"], 3);
    tok.assert();
    up.assert();
}

#[test]
fn guard_exit_code_via_cli() {
    let mut afas = Server::new();
    let entra = Server::new();
    afas.mock("GET", Matcher::Any)
        .with_body(r#"{"rows":[]}"#)
        .create();
    let dir = tempfile::tempdir().unwrap();
    let p = write_cfg(dir.path(), &afas.url(), &entra.url());
    let out = bin()
        .args(["-c", p.to_str().unwrap(), "sync"])
        .env("TEST_AFAS_TOKEN", "ABCDEF0123456789")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(20));
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["exit_code"], 20);
}

#[test]
fn apply_and_as_of_together_rejected_by_cli() {
    let dir = tempfile::tempdir().unwrap();
    let p = write_cfg(dir.path(), "http://127.0.0.1:1", "http://127.0.0.1:1");
    let out = bin()
        .args([
            "-c",
            p.to_str().unwrap(),
            "sync",
            "--apply",
            "--as-of",
            "2030-01-01",
        ])
        .env("TEST_AFAS_TOKEN", "ABCDEF0123456789")
        .env("TEST_ENTRA_SECRET", "x")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(10));
}

fn logs_server(
    statuses: &[&str],
) -> (
    mockito::ServerGuard,
    std::sync::Arc<std::sync::Mutex<String>>,
) {
    let mut entra = Server::new();
    entra
        .mock("POST", format!("/{TENANT}/oauth2/v2.0/token").as_str())
        .with_body(r#"{"access_token":"tok1","expires_in":3600}"#)
        .create();
    let seen = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let s2 = seen.clone();
    let items: Vec<Value> = statuses
        .iter()
        .map(|s| serde_json::json!({"activityDateTime":"x","provisioningAction":"update","sourceIdentity":{"id":"1"},"provisioningStatusInfo":{"status":s}}))
        .collect();
    let body = serde_json::json!({ "value": items }).to_string();
    entra
        .mock("GET", "/v1.0/auditLogs/provisioning")
        .match_query(Matcher::Any)
        .with_body_from_request(move |req| {
            *s2.lock().unwrap() = req.path_and_query().to_string();
            body.clone().into_bytes()
        })
        .create();
    (entra, seen)
}

fn run_logs(entra: &str, minutes: &str) -> std::process::Output {
    let dir = tempfile::tempdir().unwrap();
    let p = write_cfg(dir.path(), "http://127.0.0.1:1", entra);
    bin()
        .args([
            "-c",
            p.to_str().unwrap(),
            "check-logs",
            "--since-minutes",
            minutes,
        ])
        .env("TEST_ENTRA_SECRET", "x")
        .output()
        .unwrap()
}

#[test]
fn check_logs_exit_codes_and_time_window() {
    let (srv, seen) = logs_server(&["success", "skipped"]);
    let before = chrono::Utc::now();
    let out = run_logs(&srv.url(), "60");
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // the filter must be ~60 minutes in the past
    let q = seen.lock().unwrap().clone();
    let q = urlencoding_decode(&q);
    let ts = q.split("activityDateTime ge ").nth(1).unwrap()[..20].to_string();
    let t = chrono::DateTime::parse_from_rfc3339(&ts)
        .unwrap()
        .with_timezone(&chrono::Utc);
    let mins = (before - t).num_minutes();
    assert!((59..=60).contains(&mins), "venster {mins} min, query {q}");

    let (srv, _) = logs_server(&["success", "failure"]);
    assert_eq!(run_logs(&srv.url(), "60").status.code(), Some(50));
    let (srv, _) = logs_server(&[]);
    assert_eq!(run_logs(&srv.url(), "60").status.code(), Some(0));

    for bad in ["0", "10081"] {
        assert_eq!(
            run_logs("http://127.0.0.1:1", bad).status.code(),
            Some(10),
            "{bad}"
        );
    }
    // invalid arguments (clap) give exit 2
    assert_eq!(run_logs("http://127.0.0.1:1", "-5").status.code(), Some(2));
    assert_eq!(
        run_logs("http://127.0.0.1:1", "1").status.code(),
        Some(40),
        "1 minute is valid; only fails on auth"
    );
}

fn urlencoding_decode(s: &str) -> String {
    let mut out = Vec::new();
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => {
                out.push(u8::from_str_radix(&s[i + 1..i + 3], 16).unwrap());
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).unwrap()
}

#[test]
fn no_ansi_color_codes_when_not_a_terminal() {
    let out = bin()
        .args(["-c", "/does/not/exist.toml", "check-config"])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("configuration error"), "{stderr}");
    assert!(
        !stderr.contains('\u{1b}'),
        "ANSI codes in output: {stderr:?}"
    );
}

#[test]
fn exception_add_checks_the_group_like_the_gui() {
    let dir = tempfile::tempdir().unwrap();
    let p = write_cfg(dir.path(), "http://127.0.0.1:1", "http://127.0.0.1:1");
    let grp = "a1a1a1a1-0000-0000-0000-000000000001";
    let mut toml = std::fs::read_to_string(&p).unwrap();
    toml.push_str(&format!(
        "\n[roles]\nenabled = false\nclient_id = \"c0000000-0000-0000-0000-000000000001\"\ncertificate_pem = \"/x/cert.pem\"\nprivate_key_pem = \"/x/key.pem\"\ngroup_prefix = \"AFAS-\"\n[[roles.rule]]\ngroup_id = \"{grp}\"\nall = true\n"
    ));
    std::fs::write(&p, toml).unwrap();
    std::fs::create_dir_all(dir.path().join("state")).unwrap();
    let until = (chrono::Utc::now().date_naive() + chrono::Days::new(5)).to_string();
    let add = |group: &str| {
        bin()
            .env("TEST_AFAS_TOKEN", "x")
            .args([
                "-c",
                p.to_str().unwrap(),
                "exception",
                "add",
                "--employee",
                "00001",
                "--group",
                group,
                "--kind",
                "include",
                "--until",
                &until,
                "--reason",
                "test",
            ])
            .output()
            .unwrap()
    };
    let bad = add("a1a1a1a1-0000-0000-0000-00000000ffff");
    assert_ne!(bad.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&bad.stderr).contains("not in the role rules"));
    assert!(!dir.path().join("state/exceptions.json").exists());
    let ok = add(grp);
    assert_eq!(
        ok.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&ok.stderr)
    );
    assert!(dir.path().join("state/exceptions.json").exists());
}

#[test]
fn doctor_and_afas_fields_via_cli() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("state")).unwrap();
    let mut afas = Server::new();
    afas.mock("GET", Matcher::Any)
        .with_body(afas_body(&[row("00001", d("2020-01-01"), None)]))
        .create();
    let mut ms = Server::new();
    ms.mock("POST", Matcher::Regex("token".into()))
        .with_body(r#"{"access_token":"tok","expires_in":3600}"#)
        .create();
    ms.mock("GET", Matcher::Regex("auditLogs".into()))
        .with_body(r#"{"value":[]}"#)
        .create();
    let cfg = write_cfg(dir.path(), &afas.url(), &ms.url());
    let out = bin()
        .args(["-c", cfg.to_str().unwrap(), "doctor", "--json"])
        .env("TEST_AFAS_TOKEN", "ABCDEF0123456789")
        .env("TEST_ENTRA_SECRET", "s3cr3t-value-for-tests")
        .output()
        .unwrap();
    let checks: Value = serde_json::from_slice(&out.stdout).unwrap();
    let levels: Vec<&str> = checks
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["level"].as_str().unwrap())
        .collect();
    assert!(!levels.contains(&"fail"), "{checks:#}");
    // A client secret instead of a certificate is a warning: exit 3.
    assert!(levels.contains(&"warn"));
    assert_eq!(out.status.code(), Some(3), "{checks:#}");

    let out = bin()
        .args(["-c", cfg.to_str().unwrap(), "afas-fields", "--json"])
        .env("TEST_AFAS_TOKEN", "ABCDEF0123456789")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let fields: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        fields
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["field"] == "UPN"
                && f["mapped_to"] == "afas.fields.upn"
                && f["kind"] == "text with @")
    );
    assert!(!String::from_utf8_lossy(&out.stdout).contains("user00001@contoso.nl"));
}
