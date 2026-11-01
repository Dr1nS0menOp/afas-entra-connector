// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The afas-entra-sync Authors
#![allow(dead_code)]

use afas_entra_sync::config::Config;
use chrono::NaiveDate;
use serde_json::{Map, Value, json};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const TENANT: &str = "11111111-2222-3333-4444-555555555555";
pub const CLIENT: &str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
pub const SP: &str = "99999999-8888-7777-6666-555555555555";
pub const JOB: &str =
    "API2AD.b16687d38faf42adb29892cdcaf01c6e.1a03de52-b9c3-4e2c-a1e3-9145aaa8e530";

pub fn fixture(name: &str) -> String {
    format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

pub struct Opts {
    pub page_size: u32,
    pub min_records: u32,
    pub max_drop_percent: u32,
    pub max_disables: u32,
    pub max_invalid_percent: u32,
    pub max_calls: u32,
    pub batch_size: u32,
    pub prehire_days: u32,
    pub lookback_days: u32,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            page_size: 1000,
            min_records: 1,
            max_drop_percent: 10,
            max_disables: 10,
            max_invalid_percent: 10,
            max_calls: 100,
            batch_size: 50,
            prehire_days: 14,
            lookback_days: 30,
        }
    }
}

/// Writes a secret file with mode 0600, as the program requires.
pub fn write_secret(path: &Path, content: &[u8]) {
    std::fs::write(path, content).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

/// Test configuration. `auth` is "certificate" (files) or "client_secret" (env).
pub fn config_toml(
    afas_url: &str,
    entra_url: &str,
    state_dir: &Path,
    token_file: &Path,
    auth: &str,
    o: &Opts,
) -> String {
    let auth_lines = if auth == "certificate" {
        // Git does not keep mode 0600, so use a private copy of the test key.
        let key = token_file.with_file_name("test-key.pem");
        write_secret(&key, &std::fs::read(fixture("test-key.pem")).unwrap());
        format!(
            "auth = \"certificate\"\ncertificate_pem = \"{}\"\nprivate_key_pem = \"{}\"",
            fixture("test-cert.pem"),
            key.display()
        )
    } else {
        "auth = \"client_secret\"\nclient_secret_env = \"TEST_ENTRA_SECRET\"".to_string()
    };
    format!(
        r#"
[afas]
base_url = "{afas_url}/ProfitRestServices"
connector = "Entra_Medewerkers"
token_file = "{token}"
page_size = {page}
order_by_field = "Personeelsnummer"
timeout_secs = 5
max_attempts = 3

[afas.fields]
employee_id = "Personeelsnummer"
given_name = "Roepnaam"
name_prefix = "Voorvoegsel"
family_name = "Achternaam"
upn = "UPN"
email = "Email"
job_title = "Functie"
department = "Afdeling"
manager_id = "Leidinggevende"
cost_center = "Kostenplaats"
start_date = "DatumInDienst"
end_date = "DatumUitDienst"

[entra]
tenant_id = "{TENANT}"
client_id = "{CLIENT}"
{auth_lines}
service_principal_id = "{SP}"
job_id = "{JOB}"
authority = "{entra_url}"
graph_base = "{entra_url}/v1.0"
timeout_secs = 5

[policy]
timezone = "Europe/Amsterdam"
allowed_upn_domains = ["contoso.nl"]
prehire_days = {pre}
leaver_lookback_days = {look}
min_records = {min}
max_drop_percent = {drop}
max_disables_per_run = {dis}
max_invalid_percent = {inv}
max_calls_per_run = {calls}

[upload]
batch_size = {batch}
pace_ms = 125
max_attempts = 4
backoff_base_ms = 1000
backoff_max_ms = 8000
bucket_full_wait_secs = 300
max_retry_after_secs = 120

[state]
dir = "{state}"
"#,
        token = token_file.display(),
        page = o.page_size,
        pre = o.prehire_days,
        look = o.lookback_days,
        min = o.min_records,
        drop = o.max_drop_percent,
        dis = o.max_disables,
        inv = o.max_invalid_percent,
        calls = o.max_calls,
        batch = o.batch_size,
        state = state_dir.display(),
    )
}

pub fn config(afas_url: &str, entra_url: &str, dir: &Path, o: &Opts) -> Config {
    let token = dir.join("afas.token");
    write_secret(
        &token,
        b"<token><version>1</version><data>ABCDEF0123456789</data></token>",
    );
    let state = dir.join("state");
    Config::parse(&config_toml(
        afas_url,
        entra_url,
        &state,
        &token,
        "certificate",
        o,
    ))
    .expect("test config must be valid")
}

/// A valid AFAS row.
pub fn row(id: &str, start: NaiveDate, end: Option<NaiveDate>) -> Map<String, Value> {
    let v = json!({
        "Personeelsnummer": id,
        "Roepnaam": format!("Voornaam{id}"),
        "Voorvoegsel": null,
        "Achternaam": format!("Achternaam{id}"),
        "UPN": format!("user{id}@contoso.nl"),
        "Email": format!("user{id}@contoso.nl"),
        "Functie": "Medewerker",
        "Afdeling": "ICT",
        "Leidinggevende": null,
        "Kostenplaats": "4130",
        "DatumInDienst": format!("{start}T00:00:00Z"),
        "DatumUitDienst": end.map(|e| format!("{e}T00:00:00Z")),
    });
    match v {
        Value::Object(m) => m,
        _ => unreachable!(),
    }
}

pub fn d(s: &str) -> NaiveDate {
    NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap()
}

pub fn today_ams() -> NaiveDate {
    chrono::Utc::now()
        .with_timezone(&chrono_tz::Europe::Amsterdam)
        .date_naive()
}

pub fn afas_body(rows: &[Map<String, Value>]) -> String {
    json!({ "skip": 0, "take": rows.len(), "rows": rows }).to_string()
}

/// Records sleeps instead of actually sleeping.
#[derive(Clone, Default)]
pub struct SleepLog(pub Arc<Mutex<Vec<Duration>>>);

impl SleepLog {
    pub fn f(&self) -> impl Fn(Duration) + '_ {
        move |d| self.0.lock().unwrap().push(d)
    }
    pub fn all(&self) -> Vec<Duration> {
        self.0.lock().unwrap().clone()
    }
}
