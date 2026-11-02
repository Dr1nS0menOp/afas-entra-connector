// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The afas-entra-sync Authors
//! Boundaries of configuration and installer validation. Written for the mutants that
//! cargo-mutants found unguarded: every limit is tested on both sides.

use afas_entra_sync::config::{
    Config, MAX_FIELD_NAME, is_connector_name, is_field_name, is_job_id, is_upn_domain,
};
use afas_entra_sync::install::{check_connector, check_count, check_domains, check_env, check_job};

fn example() -> String {
    std::fs::read_to_string(format!(
        "{}/afas-entra-sync.example.toml",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn ok(toml: &str) -> bool {
    Config::parse(toml).is_ok()
}

fn with(from: &str, to: &str) -> String {
    let t = example();
    assert!(t.contains(from), "example has no {from:?}");
    t.replace(from, to)
}

fn plus(extra: &str) -> String {
    format!("{}\n{extra}\n", example())
}

#[test]
fn upn_domains() {
    for good in [
        "example.com",
        "sub.example-2.com",
        "a.b",
        "EXAMPLE.COM",
        "xn--bcher-kva.nl",
    ] {
        assert!(is_upn_domain(good), "{good}");
    }
    for bad in [
        "",
        "example",
        ".example.com",
        "example.com.",
        "example..com",
        "..",
        "-example.com",
        "example-.com",
        "exa mple.com",
        "user@example.com",
        "example.com/x?y",
        "(DBMS_SESSION.SLEEP(15))",
        "exam_ple.com",
    ] {
        assert!(!is_upn_domain(bad), "{bad}");
    }
    assert!(is_upn_domain(&format!("{}.com", "a".repeat(63))));
    assert!(
        !is_upn_domain(&format!("{}.com", "a".repeat(64))),
        "label > 63"
    );
    let long = format!("{}.com", vec!["a".repeat(60); 5].join("."));
    assert!(long.len() > 253 && !is_upn_domain(&long));
    // Config file and installer use the same rule.
    for (d, want) in [
        ("example.com", true),
        ("..", false),
        ("example.com/x?y", false),
    ] {
        assert_eq!(
            ok(&with(r#"["example.com"]"#, &format!("[{d:?}]"))),
            want,
            "config: {d}"
        );
        assert_eq!(check_domains(d).is_ok(), want, "installer: {d}");
    }
    assert!(check_domains("example.com, contoso.nl").is_ok());
    assert!(check_domains("example.com, ..").is_err());
    assert!(check_domains(" , ").is_err());
}

#[test]
fn field_names() {
    assert!(is_field_name("Personeelsnummer"));
    assert!(is_field_name("Personeels_nummer2"));
    assert!(is_field_name("Één"), "AFAS field names may have accents");
    assert!(is_field_name(&"a".repeat(MAX_FIELD_NAME)));
    assert!(!is_field_name(&"a".repeat(MAX_FIELD_NAME + 1)));
    for bad in [
        "",
        "Pers nummer",
        "A,B",
        "x')--",
        "a;b",
        "a.b",
        "(SELECT 1)",
    ] {
        assert!(!is_field_name(bad), "{bad}");
    }
    assert!(!ok(&with(
        r#"order_by_field = "Personeelsnummer""#,
        r#"order_by_field = "Personeelsnummer;DROP""#
    )));
    assert!(!ok(&with(
        r#"department = "Afdeling""#,
        r#"department = "Afdeling OR 1=1""#
    )));
    assert!(!ok(&with(
        r#"field = "TelefoonWerk""#,
        r#"field = "Telefoon')""#
    )));
    assert!(ok(&with(
        r#"department = "Afdeling""#,
        r#"department = "Afdeling_2""#
    )));
}

#[test]
fn connector_and_job_id_rules_are_shared() {
    for (c, want) in [
        ("Entra_Medewerkers", true),
        ("a-b_c1", true),
        ("", false),
        ("a b", false),
        ("a/b", false),
        ("a.b", false),
    ] {
        assert_eq!(is_connector_name(c), want, "{c}");
        assert_eq!(check_connector(c).is_ok(), want, "installer {c}");
        assert_eq!(
            ok(&with(
                r#"connector = "Entra_Medewerkers""#,
                &format!("connector = {c:?}")
            )),
            want,
            "config {c}"
        );
    }
    assert!(!is_connector_name(&"a".repeat(257)));
    let job = "API2AD.00000000000000000000000000000000.00000000-0000-0000-0000-000000000000";
    for (j, want) in [
        (job, true),
        ("API2AD.ab_cd.1", true),
        ("", false),
        ("API2AD x", false),
        ("API2AD/x", false),
    ] {
        assert_eq!(is_job_id(j), want, "{j}");
        assert_eq!(check_job(j).is_ok(), want, "installer {j}");
        assert_eq!(ok(&with(job, j)), want && !j.is_empty(), "config {j}");
    }
    assert!(is_job_id(&"a".repeat(256)) && !is_job_id(&"a".repeat(257)));
}

#[test]
fn installer_environment_and_count() {
    for good in [
        "1",
        "12345",
        "1234567890",
        "https://12345.rest.afas.online/ProfitRestServices",
    ] {
        assert!(check_env(good).is_ok(), "{good}");
    }
    for bad in ["", "12345678901", "12a45", "http://x", "https://x y", "abc"] {
        assert!(check_env(bad).is_err(), "{bad}");
    }
    for (n, want) in [
        ("0", false),
        ("1", true),
        ("10000000", true),
        ("10000001", false),
        ("x", false),
        ("-1", false),
    ] {
        assert_eq!(check_count(n).is_ok(), want, "{n}");
    }
}

#[test]
fn population_limits() {
    let pop = |k: &str, v: &str| plus(&format!("[population]\n{k} = {v:?}"));
    assert!(ok(&pop("name", &"n".repeat(32))));
    assert!(!ok(&pop("name", &"n".repeat(33))));
    assert!(!ok(&pop("name", "  ")));
    assert!(ok(&pop("id_prefix", "ABCDEFG-")));
    assert!(!ok(&pop("id_prefix", "ABCDEFGHI")));
    assert!(!ok(&pop("id_prefix", "")));
    assert!(!ok(&pop("id_prefix", "abc")));
    assert!(ok(&pop("employee_type", &"t".repeat(64))));
    assert!(!ok(&pop("employee_type", &"t".repeat(65))));
    assert!(!ok(&pop("employee_type", " ")));
    // Not both the fixed type and the employee_type attribute.
    let both = with(
        r#"employee_type = { enabled = false"#,
        r#"employee_type = { enabled = true"#,
    ) + "\n[population]\nemployee_type = \"Contractor\"\n";
    assert!(!ok(&both));
}

#[test]
fn policy_and_upload_limits() {
    let cases = [
        ("prehire_days = 14", "prehire_days = 365", true),
        ("prehire_days = 14", "prehire_days = 366", false),
        (
            "leaver_lookback_days = 30",
            "leaver_lookback_days = 365",
            true,
        ),
        (
            "leaver_lookback_days = 30",
            "leaver_lookback_days = 366",
            false,
        ),
        ("max_drop_percent = 10", "max_drop_percent = 100", true),
        ("max_drop_percent = 10", "max_drop_percent = 101", false),
        ("max_invalid_percent = 5", "max_invalid_percent = 100", true),
        (
            "max_invalid_percent = 5",
            "max_invalid_percent = 101",
            false,
        ),
        ("max_calls_per_run = 200", "max_calls_per_run = 0", false),
        ("min_records = 50", "min_records = 1", true),
        ("batch_size = 50", "batch_size = 1", true),
        ("batch_size = 50", "batch_size = 51", false),
        ("backoff_max_ms = 60000", "backoff_max_ms = 2000", true),
        ("backoff_max_ms = 60000", "backoff_max_ms = 1999", false),
        ("max_attempts = 6", "max_attempts = 0", false),
        ("page_size = 1000", "page_size = 10000", true),
        ("page_size = 1000", "page_size = 10001", false),
        ("timeout_secs = 120", "timeout_secs = 0", false),
        ("max_attempts = 4", "max_attempts = 0", false),
    ];
    for (from, to, want) in cases {
        assert_eq!(ok(&with(from, to)), want, "{to}");
    }
}

#[test]
fn entra_auth_combinations() {
    let no_key = with("private_key_pem = \"/etc/afas-entra-sync/key.pem\"\n", "");
    assert!(!ok(&no_key), "certificate auth needs the key");
    let secret = with(
        "auth = \"certificate\"",
        "auth = \"client_secret\"\nclient_secret_env = \"S\"",
    );
    assert!(!ok(&secret), "client_secret with certificate paths");
    let secret_only = secret
        .replace("certificate_pem = \"/etc/afas-entra-sync/cert.pem\"\n", "")
        .replace("private_key_pem = \"/etc/afas-entra-sync/key.pem\"\n", "");
    assert!(ok(&secret_only), "client_secret alone");
    assert!(!ok(&secret_only.replace("client_secret_env = \"S\"", "")));
    assert!(!ok(&with(
        "00000000-0000-0000-0000-000000000000\"\nclient_id",
        "x\"\nclient_id"
    )));
}

const IDENT: &str = "client_id = \"00000000-0000-0000-0000-000000000000\"\ncertificate_pem = \"/c.pem\"\nprivate_key_pem = \"/k.pem\"";

fn roles(extra: &str) -> String {
    plus(&format!(
        "[roles]\nenabled = true\n{IDENT}\n{extra}\n[[roles.rule]]\ngroup_id = \"11111111-1111-1111-1111-111111111111\"\nname = \"AFAS-All\"\nall = true\n"
    ))
}

#[test]
fn module_identity_and_roles_limits() {
    let base = Config::parse(&example()).unwrap();
    assert!(!base.any_module_enabled());
    let r = roles("group_prefix = \"AFAS-\"");
    assert!(Config::parse(&r).unwrap().any_module_enabled());
    assert!(!ok(&r.replace(
        "client_id = \"00000000-0000-0000-0000-000000000000\"",
        "client_id = \"x\""
    )));
    assert!(!ok(&r.replace(
        "certificate_pem = \"/c.pem\"",
        "certificate_pem = \"\""
    )));
    assert!(!ok(&r.replace(
        "private_key_pem = \"/k.pem\"",
        "private_key_pem = \"\""
    )));
    for (px, want) in [
        ("AFA", true),
        ("AF", false),
        (&*"P".repeat(32), true),
        (&*"P".repeat(33), false),
        (" AFAS", false),
    ] {
        assert_eq!(
            ok(&roles(&format!("group_prefix = {px:?}"))),
            want,
            "{px:?}"
        );
    }
    assert!(!ok(&roles(
        "group_prefix = \"AFAS-\"\nmax_changes_per_run = 0"
    )));
    assert!(ok(&roles(
        "group_prefix = \"AFAS-\"\nkeep_leavers_days = 29"
    )));
    assert!(
        !ok(&roles("group_prefix = \"AFAS-\"\nkeep_leavers_days = 30")),
        "must be < lookback"
    );
}

fn joiner(extra: &str) -> String {
    let deliver = if extra.contains("deliver_to") {
        ""
    } else {
        "deliver_to = \"manager\"\n"
    };
    plus(&format!(
        "[joiner]\nenabled = true\n{IDENT}\nsender = \"onboarding@example.com\"\n{deliver}{extra}\n"
    ))
}

#[test]
fn joiner_limits() {
    Config::parse(&joiner("")).expect("valid joiner section");
    for bad in [
        "a@b",
        "@example.com",
        "a b@example.com",
        "x/y@example.com",
        "a@b@c.d",
    ] {
        assert!(
            !ok(&joiner("").replace("onboarding@example.com", bad)),
            "{bad}"
        );
    }
    assert!(!ok(&joiner("deliver_to = \"fixed\"")));
    assert!(ok(&joiner(
        "deliver_to = \"fixed\"\nfixed_address = \"sd@example.com\""
    )));
    assert!(!ok(&joiner("fixed_address = \"not-a-mail\"")));
    let cases = [
        ("days_before_start = 14", true),
        ("days_before_start = 15", false),
        ("start_hour = 23", true),
        ("start_hour = 24", false),
        ("lifetime_minutes = 60", true),
        ("lifetime_minutes = 59", false),
        ("lifetime_minutes = 43200", true),
        ("lifetime_minutes = 43201", false),
        ("max_per_run = 0", false),
        ("subject = \"Your code {tap}\"", false),
        ("body = \"no code here\"", false),
    ];
    for (line, want) in cases {
        assert_eq!(ok(&joiner(line)), want, "{line}");
    }
}

#[test]
fn leaver_and_webhook_limits() {
    let leaver = |extra: &str| plus(&format!("[leaver]\nenabled = true\n{IDENT}\n{extra}\n"));
    assert!(ok(&leaver("")));
    for (line, want) in [
        ("grace_days = 1", true),
        ("grace_days = 0", false),
        ("grace_days = 90", true),
        ("grace_days = 91", false),
        ("max_per_run = 0", false),
        ("revoke_sessions = false", false),
        ("revoke_sessions = false\nauto_reply = \"Gone.\"", true),
        ("auto_reply = \" \"", false),
    ] {
        assert_eq!(ok(&leaver(line)), want, "{line}");
    }
    assert!(ok(&leaver(&format!("auto_reply = {:?}", "x".repeat(4000)))));
    assert!(!ok(&leaver(&format!(
        "auto_reply = {:?}",
        "x".repeat(4001)
    ))));

    let hook = |extra: &str| {
        plus(&format!(
            "[webhook]\nenabled = true\nurl = \"https://itsm.example.com/h\"\n{extra}\n"
        ))
    };
    assert!(ok(&hook("secret_env = \"S\"")));
    assert!(!ok(&hook("")), "a secret is required");
    assert!(!ok(&hook("secret_env = \"S\"\nsecret_file = \"/s\"")));
    assert!(!ok(&hook("secret_env = \"S\"\nevents = []")));
    for (t, want) in [("1", true), ("0", false), ("120", true), ("121", false)] {
        assert_eq!(
            ok(&hook(&format!("secret_env = \"S\"\ntimeout_secs = {t}"))),
            want,
            "{t}"
        );
    }
    assert!(!ok(&hook("secret_env = \"S\"\nmax_per_run = 0")));
    assert!(!ok(&hook("secret_env = \"S\"").replace(
        "https://itsm.example.com/h",
        "http://itsm.example.com/h"
    )));
    assert!(ok(
        &hook("secret_env = \"S\"").replace("https://itsm.example.com/h", "http://127.0.0.1:9/h")
    ));
}
