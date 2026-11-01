// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The afas-entra-sync Authors
//! Converts an AFAS row into a validated employee.
//!
//! Principle: anything that is not 100% right is NOT sent. A record that is
//! not sent is left alone by the provisioning engine; that is always safer
//! than sending a partial or wrong record.

use crate::config::{ExtraFields, FieldMap};
use chrono::{Datelike, NaiveDate};
use serde_json::{Map, Value};

/// Length limits from the AD schema (rangeUpper). Entra ID is more lenient;
/// we keep the strictest because the target can be AD.
pub const MAX_EMPLOYEE_ID: usize = 16;
pub const MAX_GIVEN_NAME: usize = 64;
pub const MAX_FAMILY_NAME: usize = 64;
pub const MAX_DISPLAY_NAME: usize = 256;
pub const MAX_TITLE: usize = 128;
pub const MAX_DEPARTMENT: usize = 64;
pub const MAX_COST_CENTER: usize = 64;
pub const MAX_UPN: usize = 113;
pub const MAX_UPN_LOCAL: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Employee {
    pub employee_id: String,
    pub given_name: String,
    /// Family name including prefix ("de Vries").
    pub family_name: String,
    pub display_name: String,
    pub upn: String,
    pub email: Option<String>,
    pub job_title: Option<String>,
    pub department: Option<String>,
    pub manager_id: Option<String>,
    pub cost_center: Option<String>,
    pub start_date: NaiveDate,
    pub end_date: Option<NaiveDate>,
    /// Only filled for attributes switched on in `[afas.fields.extra]`.
    pub extra: Extra,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Extra {
    pub phone_work: Option<String>,
    pub phone_mobile: Option<String>,
    pub office: Option<String>,
    pub company: Option<String>,
    pub employee_type: Option<String>,
    pub job_profile: Option<String>,
    pub street: Option<String>,
    pub postal_code: Option<String>,
    pub city: Option<String>,
    pub country: Option<String>,
}

pub const MAX_JOB_PROFILE: usize = 64;
pub const MAX_STREET: usize = 128;
pub const MAX_POSTAL: usize = 16;
pub const MAX_CITY: usize = 128;
pub const MAX_PHONE: usize = 64;
pub const MAX_OFFICE: usize = 128;
pub const MAX_COMPANY: usize = 64;
pub const MAX_EMPLOYEE_TYPE: usize = 64;

/// Row-level data error: only this record is excluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RowError {
    /// Employee number if readable; otherwise `None`.
    pub employee_id: Option<String>,
    pub reason: String,
}

/// Checks that every row contains every configured field (even if the value is null).
/// A missing field means the mapping or the GetConnector is wrong: that is fatal,
/// not per row, because it affects all records.
pub fn check_schema(rows: &[Map<String, Value>], fields: &FieldMap) -> Result<(), String> {
    for (i, row) in rows.iter().enumerate() {
        for f in fields.all_fields() {
            if !row.contains_key(f) {
                return Err(format!(
                    "field '{f}' is missing in AFAS row {} (check afas.fields and the GetConnector)",
                    i + 1
                ));
            }
        }
    }
    Ok(())
}

pub fn parse_row(row: &Map<String, Value>, f: &FieldMap) -> Result<Employee, RowError> {
    // Employee number first, so every later error can be linked to it.
    let employee_id = match text(row, &f.employee_id) {
        Ok(Some(id)) => id,
        Ok(None) => {
            return Err(RowError {
                employee_id: None,
                reason: "employee number is missing".into(),
            });
        }
        Err(e) => {
            return Err(RowError {
                employee_id: None,
                reason: format!("employee number: {e}"),
            });
        }
    };
    // Population prefix before all checks, so the length limit covers the whole.
    let employee_id = match &f.population.id_prefix {
        Some(px) => format!("{px}{employee_id}"),
        None => employee_id,
    };
    let fail = |reason: String| RowError {
        employee_id: Some(employee_id.clone()),
        reason,
    };

    if employee_id.chars().count() > MAX_EMPLOYEE_ID {
        return Err(fail(format!(
            "employee number longer than {MAX_EMPLOYEE_ID} characters"
        )));
    }
    if employee_id.chars().any(char::is_whitespace) {
        return Err(fail("employee number contains spaces".into()));
    }

    let req = |field: &str, label: &str, max: usize| -> Result<String, RowError> {
        match text(row, field) {
            Ok(Some(v)) => check_len(v, label, max).map_err(fail),
            Ok(None) => Err(fail(format!("{label} is missing"))),
            Err(e) => Err(fail(format!("{label}: {e}"))),
        }
    };
    let opt =
        |field: &Option<String>, label: &str, max: usize| -> Result<Option<String>, RowError> {
            let Some(field) = field else { return Ok(None) };
            match text(row, field) {
                Ok(Some(v)) => check_len(v, label, max).map(Some).map_err(fail),
                Ok(None) => Ok(None),
                Err(e) => Err(fail(format!("{label}: {e}"))),
            }
        };

    let given_name = req(&f.given_name, "given name", MAX_GIVEN_NAME)?;
    let family_raw = req(&f.family_name, "family name", MAX_FAMILY_NAME)?;
    let prefix = opt(&f.name_prefix, "name prefix", MAX_FAMILY_NAME)?;
    let family_name = match &prefix {
        Some(p) => format!("{p} {family_raw}"),
        None => family_raw,
    };
    let family_name =
        check_len(family_name, "family name incl. prefix", MAX_FAMILY_NAME).map_err(fail)?;

    let display_name = match opt(&f.display_name, "display name", MAX_DISPLAY_NAME)? {
        Some(d) => d,
        None => check_len(
            format!("{given_name} {family_name}"),
            "display name",
            MAX_DISPLAY_NAME,
        )
        .map_err(fail)?,
    };

    let upn = req(&f.upn, "UPN", MAX_UPN)?;
    let email = opt(&f.email, "email", MAX_UPN)?;
    if let Some(e) = &email
        && !looks_like_email(e)
    {
        return Err(fail(format!("email address '{e}' is invalid")));
    }
    let job_title = opt(&f.job_title, "job title", MAX_TITLE)?;
    let department = opt(&f.department, "department", MAX_DEPARTMENT)?;
    let manager_id = opt(&f.manager_id, "manager", MAX_EMPLOYEE_ID)?;
    if let Some(m) = &manager_id
        && m.chars().any(char::is_whitespace)
    {
        return Err(fail("manager employee number contains spaces".into()));
    }
    let cost_center = opt(&f.cost_center, "cost center", MAX_COST_CENTER)?;

    let start_date = match date(row, &f.start_date) {
        Ok(Some(d)) => d,
        Ok(None) => return Err(fail("start date is missing".into())),
        Err(e) => return Err(fail(format!("start date: {e}"))),
    };
    let end_date = date(row, &f.end_date).map_err(|e| fail(format!("end date: {e}")))?;
    if let Some(end) = end_date
        && end < start_date
    {
        return Err(fail(format!(
            "end date {end} is before start date {start_date}"
        )));
    }

    let x = &f.extra;
    let extra = Extra {
        phone_work: opt_phone(row, ExtraFields::active(&x.phone_work), "work phone")
            .map_err(fail)?,
        phone_mobile: opt_phone(row, ExtraFields::active(&x.phone_mobile), "mobile phone")
            .map_err(fail)?,
        office: opt(
            &ExtraFields::active(&x.office).map(str::to_string),
            "office",
            MAX_OFFICE,
        )?,
        company: opt(
            &ExtraFields::active(&x.company).map(str::to_string),
            "company",
            MAX_COMPANY,
        )?,
        employee_type: opt(
            &ExtraFields::active(&x.employee_type).map(str::to_string),
            "employee type",
            MAX_EMPLOYEE_TYPE,
        )?,
        job_profile: opt(
            &ExtraFields::active(&x.job_profile).map(str::to_string),
            "job profile",
            MAX_JOB_PROFILE,
        )?,
        street: opt(
            &ExtraFields::active(&x.street).map(str::to_string),
            "street",
            MAX_STREET,
        )?,
        postal_code: opt(
            &ExtraFields::active(&x.postal_code).map(str::to_string),
            "postal code",
            MAX_POSTAL,
        )?,
        city: opt(
            &ExtraFields::active(&x.city).map(str::to_string),
            "city",
            MAX_CITY,
        )?,
        country: opt(
            &ExtraFields::active(&x.country).map(str::to_string),
            "country",
            2,
        )?,
    };
    let mut extra = extra;
    if let Some(c) = &extra.country
        && !(c.len() == 2 && c.chars().all(|ch| ch.is_ascii_uppercase()))
    {
        return Err(fail(format!(
            "country '{c}' must be a 2-letter uppercase country code (e.g. NL)"
        )));
    }
    if let Some(t) = &f.population.employee_type {
        extra.employee_type = Some(t.clone());
    }

    Ok(Employee {
        extra,
        employee_id,
        given_name,
        family_name,
        display_name,
        upn,
        email,
        job_title,
        department,
        manager_id,
        cost_center,
        start_date,
        end_date,
    })
}

fn check_len(v: String, label: &str, max: usize) -> Result<String, String> {
    if v.chars().count() > max {
        Err(format!("{label} is longer than {max} characters"))
    } else {
        Ok(v)
    }
}

/// Reads a text field: trims, collapses internal whitespace and rejects
/// control characters. Empty text becomes `None`.
pub fn text(row: &Map<String, Value>, field: &str) -> Result<Option<String>, String> {
    let raw = match row.get(field) {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => {
            if let Some(i) = n.as_i64() {
                i.to_string()
            } else if let Some(u) = n.as_u64() {
                u.to_string()
            } else {
                return Err(format!("number '{n}' is not an integer"));
            }
        }
        Some(other) => return Err(format!("unexpected type ({})", type_name(other))),
    };
    if raw
        .chars()
        .any(|c| c.is_control() && !matches!(c, '\t' | '\n' | '\r'))
    {
        return Err("contains control characters".into());
    }
    let cleaned = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    Ok(if cleaned.is_empty() {
        None
    } else {
        Some(cleaned)
    })
}

/// Reads a date. AFAS delivers dates as `2024-01-01T00:00:00Z` (or without
/// a time). They are calendar dates: we take the date part literally and
/// deliberately do NOT convert to a time zone.
pub fn date(row: &Map<String, Value>, field: &str) -> Result<Option<NaiveDate>, String> {
    let s = match row.get(field) {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::String(s)) => s.trim(),
        Some(other) => return Err(format!("unexpected type ({})", type_name(other))),
    };
    if s.is_empty() {
        return Ok(None);
    }
    parse_afas_date(s).map(Some)
}

pub fn parse_afas_date(s: &str) -> Result<NaiveDate, String> {
    let date_part = s.get(..10).ok_or_else(|| format!("'{s}' is not a date"))?;
    let rest = &s[10..];
    // Allowed after the date: nothing, or a time starting with 'T' or a space.
    if !(rest.is_empty() || rest.starts_with('T') || rest.starts_with(' ')) {
        return Err(format!("'{s}' is not a date"));
    }
    if !rest.is_empty() {
        let t = &rest[1..];
        let ok = t.len() >= 8
            && t.as_bytes()[2] == b':'
            && t.as_bytes()[5] == b':'
            && t[..2].bytes().all(|b| b.is_ascii_digit())
            && t[3..5].bytes().all(|b| b.is_ascii_digit())
            && t[6..8].bytes().all(|b| b.is_ascii_digit());
        if !ok {
            return Err(format!("'{s}' has an invalid time part"));
        }
        // A time other than midnight points to a time zone conversion
        // somewhere in the chain; then the date part is not reliable.
        if &t[..8] != "00:00:00" {
            return Err(format!(
                "'{s}' has a time other than 00:00:00; the date is ambiguous"
            ));
        }
        if !valid_time_suffix(&t[8..]) {
            return Err(format!("'{s}' has an invalid time part"));
        }
    }
    let d = NaiveDate::parse_from_str(date_part, "%Y-%m-%d")
        .map_err(|_| format!("'{s}' is not a valid date"))?;
    if d.year_ce().1 < 1900 || d.year_ce().1 > 2200 {
        return Err(format!("'{s}' is outside the valid range"));
    }
    Ok(d)
}

/// After `HH:MM:SS` may follow: nothing, `.000…` (zeros only), and then
/// optionally `Z` or `+HH:MM` / `-HH:MM`.
fn valid_time_suffix(mut s: &str) -> bool {
    if let Some(frac) = s.strip_prefix('.') {
        let n = frac.bytes().take_while(u8::is_ascii_digit).count();
        if n == 0 || !frac[..n].bytes().all(|b| b == b'0') {
            return false;
        }
        s = &frac[n..];
    }
    match s.as_bytes() {
        [] | [b'Z'] => true,
        [b'+' | b'-', h1, h2, b':', m1, m2] => [h1, h2, m1, m2].iter().all(|b| b.is_ascii_digit()),
        _ => false,
    }
}

fn type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "text",
        Value::Array(_) => "list",
        Value::Object(_) => "object",
    }
}

/// UPN check following the Entra rules for the local part:
/// A-Z a-z 0-9 ' . - _ ! # ^ ~, not starting or ending with a dot and no "..".
pub fn validate_upn(upn: &str, allowed_domains: &[String]) -> Result<(), String> {
    if upn.chars().count() > MAX_UPN {
        return Err(format!("UPN longer than {MAX_UPN} characters"));
    }
    let mut parts = upn.split('@');
    let (Some(local), Some(domain), None) = (parts.next(), parts.next(), parts.next()) else {
        return Err(format!("UPN '{upn}' must contain exactly one '@'"));
    };
    if local.is_empty() || local.len() > MAX_UPN_LOCAL {
        return Err(format!(
            "UPN '{upn}': local part empty or longer than {MAX_UPN_LOCAL} characters"
        ));
    }
    if local.starts_with('.') || local.ends_with('.') || local.contains("..") {
        return Err(format!("UPN '{upn}': invalid dot in local part"));
    }
    if let Some(bad) = local.chars().find(|c| {
        !(c.is_ascii_alphanumeric() || matches!(c, '\'' | '.' | '-' | '_' | '!' | '#' | '^' | '~'))
    }) {
        return Err(format!(
            "UPN '{upn}': invalid character '{bad}' in local part"
        ));
    }
    if !allowed_domains
        .iter()
        .any(|d| d.eq_ignore_ascii_case(domain))
    {
        return Err(format!(
            "UPN '{upn}': domain '{domain}' is not in allowed_upn_domains"
        ));
    }
    Ok(())
}

fn looks_like_email(s: &str) -> bool {
    let mut parts = s.split('@');
    matches!(
        (parts.next(), parts.next(), parts.next()),
        (Some(l), Some(d), None) if !l.is_empty() && d.contains('.') && !d.starts_with('.') && !d.ends_with('.')
    ) && !s.chars().any(char::is_whitespace)
}

/// Phone number: only digits, spaces and `+ - ( ) .`, at least 6 digits.
fn opt_phone(
    row: &Map<String, Value>,
    field: Option<&str>,
    label: &str,
) -> Result<Option<String>, String> {
    let Some(field) = field else { return Ok(None) };
    let Some(v) = text(row, field).map_err(|e| format!("{label}: {e}"))? else {
        return Ok(None);
    };
    if v.chars().count() > MAX_PHONE {
        return Err(format!("{label} is longer than {MAX_PHONE} characters"));
    }
    if !v
        .chars()
        .all(|c| c.is_ascii_digit() || matches!(c, '+' | '-' | '(' | ')' | '.' | ' '))
    {
        return Err(format!("{label} '{v}' contains invalid characters"));
    }
    if v.chars().filter(char::is_ascii_digit).count() < 6 {
        return Err(format!("{label} '{v}' has too few digits"));
    }
    Ok(Some(v))
}
