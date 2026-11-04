// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The afas-entra-sync Authors
//! Extra attributes with on/off toggles (`[afas.fields.extra]`).

mod common;

use afas_entra_sync::config::Config;
use afas_entra_sync::model::{check_schema, parse_row};
use afas_entra_sync::plan::{PlanInput, build_plan};
use afas_entra_sync::scim::{AFAS_SCHEMA, ENTERPRISE_SCHEMA, user_data};
use common::*;
use serde_json::{Value, json};

const EXTRA_ALL: &str = r#"
[afas.fields.extra]
phone_work = { enabled = true, field = "TelWerk" }
phone_mobile = { enabled = true, field = "Mobiel" }
office = { enabled = true, field = "Standplaats" }
company = { enabled = true, field = "Werkgever" }
employee_type = { enabled = true, field = "Soort" }
send_hire_date = true
send_leave_date = true
"#;

fn cfg_with(extra: &str) -> (Config, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let tok = dir.path().join("t");
    let toml = config_toml(
        "http://127.0.0.1:1",
        "http://127.0.0.1:1",
        dir.path(),
        &tok,
        "certificate",
        &Opts::default(),
    ) + extra;
    (Config::parse(&toml).expect("config"), dir)
}

fn full_row() -> serde_json::Map<String, Value> {
    let mut r = row("1", d("2020-01-01"), Some(d("2027-06-30")));
    r.insert("TelWerk".into(), json!("030 123 45 67"));
    r.insert("Mobiel".into(), json!("+31 6 12345678"));
    r.insert("Standplaats".into(), json!("Zwolle"));
    r.insert("Werkgever".into(), json!("Contoso"));
    r.insert("Soort".into(), json!("Contractor"));
    r
}

fn data_for(c: &Config, r: serde_json::Map<String, Value>) -> Value {
    let rows = vec![r];
    let p = build_plan(PlanInput {
        rows: &rows,
        fields: &c.afas.fields,
        policy: &c.policy,
        batch_size: 50,
        today: d("2026-10-31"),
        previous: None,
        allow_mass_disable: false,
        allow_mass_create: false,
        allow_upn_changes: false,
    });
    assert!(p.exclusions.is_empty(), "{:?}", p.exclusions);
    user_data(&p.records[0])
}

#[test]
fn all_extras_on_produce_expected_scim() {
    let (c, _t) = cfg_with(EXTRA_ALL);
    let data = data_for(&c, full_row());
    assert_eq!(
        data["phoneNumbers"],
        json!([{ "value": "030 123 45 67", "type": "work" }])
    );
    assert_eq!(data["userType"], "Contractor");
    assert_eq!(data[ENTERPRISE_SCHEMA]["organization"], "Contoso");
    let x = &data[AFAS_SCHEMA];
    assert_eq!(x["mobilePhone"], "+31 6 12345678");
    assert_eq!(x["officeLocation"], "Zwolle");
    assert_eq!(x["hireDate"], "2020-01-01");
    assert_eq!(x["leaveDate"], "2027-06-30");
    assert!(
        data["schemas"]
            .as_array()
            .unwrap()
            .contains(&json!(AFAS_SCHEMA))
    );
}

#[test]
fn without_extra_section_output_is_unchanged() {
    let (c, _t) = cfg_with("");
    let data = data_for(&c, full_row());
    for k in ["phoneNumbers", "userType", AFAS_SCHEMA] {
        assert!(data.get(k).is_none(), "{k}");
    }
    assert!(data[ENTERPRISE_SCHEMA].get("organization").is_none());
    assert_eq!(data["schemas"].as_array().unwrap().len(), 2);
}

#[test]
fn disabled_toggle_is_not_read_or_required() {
    let (c, _t) = cfg_with(
        "\n[afas.fields.extra]\nphone_mobile = { enabled = false, field = \"BestaatNiet\" }\n",
    );
    // Field missing in AFAS, but switched off: no schema error, nothing sent.
    let rows = vec![row("1", d("2020-01-01"), None)];
    assert!(check_schema(&rows, &c.afas.fields).is_ok());
    let data = data_for(&c, rows[0].clone());
    assert!(data.get(AFAS_SCHEMA).is_none());
}

#[test]
fn enabled_toggle_field_must_exist_in_afas() {
    let (c, _t) =
        cfg_with("\n[afas.fields.extra]\noffice = { enabled = true, field = \"Standplaats\" }\n");
    let rows = vec![row("1", d("2020-01-01"), None)];
    assert!(
        check_schema(&rows, &c.afas.fields)
            .unwrap_err()
            .contains("Standplaats")
    );
}

#[test]
fn leave_date_only_when_present_and_empty_values_omitted() {
    let (c, _t) = cfg_with(EXTRA_ALL);
    let mut r = full_row();
    r.insert("DatumUitDienst".into(), Value::Null);
    for k in ["TelWerk", "Mobiel", "Standplaats", "Werkgever", "Soort"] {
        r.insert(k.into(), json!("  "));
    }
    let data = data_for(&c, r);
    assert!(data.get("phoneNumbers").is_none() && data.get("userType").is_none());
    let x = &data[AFAS_SCHEMA];
    assert_eq!(x.as_object().unwrap().len(), 1, "alleen hireDate: {x}");
    assert_eq!(x["hireDate"], "2020-01-01");
}

#[test]
fn phone_validation() {
    let (c, _t) = cfg_with(EXTRA_ALL);
    for ok in ["0301234567", "+31 (0)30-123.45.67", "030 123456"] {
        let mut r = full_row();
        r.insert("TelWerk".into(), json!(ok));
        assert!(parse_row(&r, &c.afas.fields).is_ok(), "{ok}");
    }
    for bad in ["12345", "030-ABC-1234", "030 123 456 x12", &"1".repeat(65)] {
        let mut r = full_row();
        r.insert("Mobiel".into(), json!(bad));
        let e = parse_row(&r, &c.afas.fields).unwrap_err();
        assert_eq!(e.employee_id.as_deref(), Some("1"));
        assert!(e.reason.contains("mobile phone"), "{bad}: {}", e.reason);
    }
}

#[test]
fn extra_length_limits_are_exact() {
    let (c, _t) = cfg_with(EXTRA_ALL);
    for (field, max) in [("Standplaats", 128usize), ("Werkgever", 64), ("Soort", 64)] {
        let mut r = full_row();
        r.insert(field.into(), json!("x".repeat(max)));
        assert!(parse_row(&r, &c.afas.fields).is_ok(), "{field}");
        r.insert(field.into(), json!("x".repeat(max + 1)));
        assert!(parse_row(&r, &c.afas.fields).is_err(), "{field}");
    }
}

#[test]
fn config_rejects_mistakes_in_extra() {
    let dir = tempfile::tempdir().unwrap();
    let tok = dir.path().join("t");
    let base = config_toml(
        "http://127.0.0.1:1",
        "http://127.0.0.1:1",
        dir.path(),
        &tok,
        "certificate",
        &Opts::default(),
    );
    for (name, extra) in [
        (
            "unknown attribute",
            "\n[afas.fields.extra]\nfax = { enabled = true, field = \"Fax\" }\n",
        ),
        (
            "typo in toggle",
            "\n[afas.fields.extra]\noffice = { enable = true, field = \"X\" }\n",
        ),
        (
            "field already used",
            "\n[afas.fields.extra]\noffice = { enabled = true, field = \"Afdeling\" }\n",
        ),
        (
            "two extras same field",
            "\n[afas.fields.extra]\noffice = { enabled = true, field = \"X\" }\ncompany = { enabled = true, field = \"X\" }\n",
        ),
        (
            "empty field",
            "\n[afas.fields.extra]\noffice = { enabled = true, field = \" \" }\n",
        ),
    ] {
        assert!(
            Config::parse(&(base.clone() + extra)).is_err(),
            "should have been refused: {name}"
        );
    }
    // a switched-off attribute may reuse a field name
    assert!(
        Config::parse(
            &(base + "\n[afas.fields.extra]\noffice = { enabled = false, field = \"Afdeling\" }\n")
        )
        .is_ok()
    );
}

const EXTRA_ADDR: &str = r#"
[afas.fields.extra]
job_profile = { enabled = true, field = "Functieprofiel" }
street = { enabled = true, field = "Straat" }
postal_code = { enabled = true, field = "Postcode" }
city = { enabled = true, field = "Plaats" }
country = { enabled = true, field = "Land" }
"#;

fn addr_row() -> serde_json::Map<String, Value> {
    let mut r = row("1", d("2020-01-01"), None);
    r.insert("Functieprofiel".into(), json!("FP-ICT-01"));
    r.insert("Straat".into(), json!("Kanaalweg 1"));
    r.insert("Postcode".into(), json!("3526 KL"));
    r.insert("Plaats".into(), json!("Zwolle"));
    r.insert("Land".into(), json!("NL"));
    r
}

#[test]
fn work_address_and_job_profile() {
    let (c, _t) = cfg_with(EXTRA_ADDR);
    let data = data_for(&c, addr_row());
    assert_eq!(
        data["addresses"],
        json!([{ "type": "work", "streetAddress": "Kanaalweg 1", "postalCode": "3526 KL",
                 "locality": "Zwolle", "country": "NL" }])
    );
    assert_eq!(data[AFAS_SCHEMA]["jobProfile"], "FP-ICT-01");
}

#[test]
fn partial_address_only_sends_present_parts() {
    let (c, _t) = cfg_with(EXTRA_ADDR);
    let mut r = addr_row();
    r.insert("Straat".into(), Value::Null);
    r.insert("Postcode".into(), Value::Null);
    let data = data_for(&c, r);
    assert_eq!(
        data["addresses"],
        json!([{ "type": "work", "locality": "Zwolle", "country": "NL" }])
    );
    let mut r = addr_row();
    for k in ["Straat", "Postcode", "Plaats", "Land"] {
        r.insert(k.into(), Value::Null);
    }
    assert!(data_for(&c, r).get("addresses").is_none());
}

#[test]
fn country_must_be_two_uppercase_letters() {
    let (c, _t) = cfg_with(EXTRA_ADDR);
    for bad in ["nl", "NLD", "N1", "Nederland"] {
        let mut r = addr_row();
        r.insert("Land".into(), json!(bad));
        assert!(parse_row(&r, &c.afas.fields).is_err(), "{bad}");
    }
}

#[test]
fn population_prefix_and_fixed_type() {
    let (c, _t) = cfg_with(
        "\n[population]\nname = \"inhuur\"\nid_prefix = \"INH-\"\nemployee_type = \"Contractor\"\n",
    );
    let e = parse_row(&row("1001", d("2020-01-01"), None), &c.afas.fields).unwrap();
    assert_eq!(e.employee_id, "INH-1001");
    assert_eq!(e.extra.employee_type.as_deref(), Some("Contractor"));
    let data = data_for(&c, row("1001", d("2020-01-01"), None));
    assert_eq!(data["externalId"], "INH-1001");
    assert_eq!(data[ENTERPRISE_SCHEMA]["employeeNumber"], "INH-1001");
    assert_eq!(data["userType"], "Contractor");
    // the prefix counts towards the length limit of 16
    assert!(parse_row(&row("123456789012", d("2020-01-01"), None), &c.afas.fields).is_ok());
    assert!(parse_row(&row("1234567890123", d("2020-01-01"), None), &c.afas.fields).is_err());
}

#[test]
fn population_config_is_validated() {
    let dir = tempfile::tempdir().unwrap();
    let tok = dir.path().join("t");
    let base = config_toml(
        "http://127.0.0.1:1",
        "http://127.0.0.1:1",
        dir.path(),
        &tok,
        "certificate",
        &Opts::default(),
    );
    for (name, extra) in [
        ("kleine letters", "\n[population]\nid_prefix = \"inh-\"\n"),
        ("too long", "\n[population]\nid_prefix = \"ABCDEFGHI\"\n"),
        ("empty", "\n[population]\nid_prefix = \"\"\n"),
        ("onbekend veld", "\n[population]\nprefix = \"INH-\"\n"),
        (
            "duplicate employee_type",
            "\n[population]\nemployee_type = \"Intern\"\n[afas.fields.extra]\nemployee_type = { enabled = true, field = \"Soort\" }\n",
        ),
    ] {
        assert!(
            Config::parse(&(base.clone() + extra)).is_err(),
            "should have been refused: {name}"
        );
    }
    assert!(
        Config::parse(&(base + "\n[population]\nname = \"stagiairs\"\nid_prefix = \"STG-\"\n"))
            .is_ok()
    );
}
