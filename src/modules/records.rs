// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The afas-entra-sync Authors
//! Access log (who got or lost which access, when) and exceptions (manual,
//! time-limited deviations from the role rules).

use chrono::NaiveDate;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::Path;

pub const ACCESS_LOG: &str = "access.log";
pub const EXCEPTIONS_FILE: &str = "exceptions.json";

/// One line of the access log (JSON Lines, append-only).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccessEntry {
    pub utc: String,
    pub module: String,
    pub action: String,
    pub employee_id: Option<String>,
    pub upn: Option<String>,
    pub target: Option<String>,
    pub ok: bool,
    pub detail: Option<String>,
    pub actor: String,
}

pub fn append_access(dir: &Path, e: &AccessEntry) -> Result<(), String> {
    let line = serde_json::to_string(e).map_err(|e| e.to_string())?;
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(dir.join(ACCESS_LOG))
        .map_err(|e| format!("access log: {e}"))?;
    // One write per line: a crash cannot interleave or split it.
    f.write_all(format!("{line}\n").as_bytes())
        .map_err(|e| format!("access log: {e}"))
}

/// Entries, oldest first, optionally for one employee and from a date (UTC).
pub fn read_access(
    dir: &Path,
    employee: Option<&str>,
    since: Option<NaiveDate>,
) -> Result<Vec<AccessEntry>, String> {
    let text = match std::fs::read_to_string(dir.join(ACCESS_LOG)) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("access log: {e}")),
    };
    let since_s = since.map(|d| d.format("%Y-%m-%d").to_string());
    Ok(text
        .lines()
        .filter_map(|l| serde_json::from_str::<AccessEntry>(l).ok())
        .filter(|e| employee.is_none_or(|x| e.employee_id.as_deref() == Some(x)))
        .filter(|e| since_s.as_deref().is_none_or(|s| e.utc.as_str() >= s))
        .collect())
}

/// CSV with a fixed column order; fields are quoted and inner quotes doubled.
/// Cells starting with = + - @ are prefixed with ' so spreadsheets do not run them.
pub fn access_csv(entries: &[AccessEntry]) -> String {
    fn cell(s: &str) -> String {
        let s = if s.starts_with(['=', '+', '-', '@', '\t', '\r']) {
            format!("'{s}")
        } else {
            s.to_string()
        };
        format!("\"{}\"", s.replace('"', "\"\""))
    }
    let mut out = String::from("utc,module,action,employee_id,upn,target,ok,detail,actor\n");
    for e in entries {
        let row = [
            e.utc.as_str(),
            e.module.as_str(),
            e.action.as_str(),
            e.employee_id.as_deref().unwrap_or(""),
            e.upn.as_deref().unwrap_or(""),
            e.target.as_deref().unwrap_or(""),
            if e.ok { "true" } else { "false" },
            e.detail.as_deref().unwrap_or(""),
            e.actor.as_str(),
        ];
        out.push_str(&row.map(cell).join(","));
        out.push('\n');
    }
    out
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExceptionKind {
    /// Keep or put the employee in the group, whatever the rules say.
    Include,
    /// Keep the employee out of the group, whatever the rules say.
    Exclude,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Exception {
    pub id: String,
    pub employee_id: String,
    pub group_id: String,
    pub kind: ExceptionKind,
    /// Last day the exception applies (inclusive).
    pub until: NaiveDate,
    pub reason: String,
    pub created_by: String,
    pub created_utc: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Exceptions {
    pub version: u32,
    pub items: Vec<Exception>,
}

pub fn load_exceptions(dir: &Path) -> Result<Exceptions, String> {
    match std::fs::read_to_string(dir.join(EXCEPTIONS_FILE)) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Exceptions {
            version: 1,
            items: vec![],
        }),
        Err(e) => Err(format!("exceptions: {e}")),
        Ok(t) => serde_json::from_str(&t).map_err(|e| {
            format!("{EXCEPTIONS_FILE} is corrupt ({e}); repair it or delete it deliberately")
        }),
    }
}

pub fn save_exceptions(dir: &Path, x: &Exceptions) -> Result<(), String> {
    let j = serde_json::to_vec_pretty(x).map_err(|e| e.to_string())?;
    crate::state::write_atomic(&dir.join(EXCEPTIONS_FILE), &j).map_err(|e| e.to_string())
}

/// Validates and adds an exception; returns its id.
#[allow(clippy::too_many_arguments)]
pub fn add_exception(
    dir: &Path,
    employee_id: &str,
    group_id: &str,
    kind: ExceptionKind,
    until: NaiveDate,
    reason: &str,
    created_by: &str,
    today: NaiveDate,
) -> Result<String, String> {
    let employee_id = employee_id.trim();
    if employee_id.is_empty() || employee_id.len() > 16 || employee_id.contains(char::is_whitespace)
    {
        return Err("employee number: 1 to 16 characters, no spaces".into());
    }
    if !crate::config::is_guid(group_id.trim()) {
        return Err("group id must be a GUID".into());
    }
    if until < today {
        return Err("until is in the past".into());
    }
    if until > today + chrono::Days::new(366) {
        return Err("until can be at most one year ahead".into());
    }
    let reason = reason.trim();
    if reason.is_empty() || reason.len() > 500 || reason.chars().any(char::is_control) {
        return Err("reason: 1 to 500 characters".into());
    }
    let mut x = load_exceptions(dir)?;
    if x.items.len() >= 10_000 {
        return Err("too many exceptions".into());
    }
    let id = uuid::Uuid::new_v4().to_string();
    x.version = 1;
    x.items.push(Exception {
        id: id.clone(),
        employee_id: employee_id.to_string(),
        group_id: group_id.trim().to_ascii_lowercase(),
        kind,
        until,
        reason: reason.to_string(),
        created_by: created_by.to_string(),
        created_utc: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    });
    save_exceptions(dir, &x)?;
    Ok(id)
}

/// Checks that make an exception useful for this config: the group must be one the role
/// rules manage, and the employee number must carry this staff category's prefix (the
/// number as it appears in reports), or it would never match anyone.
pub fn check_new_exception(
    cfg: &crate::config::Config,
    employee_id: &str,
    group_id: &str,
) -> Result<(), String> {
    let in_rules = cfg.roles.as_ref().is_some_and(|r| {
        r.rules
            .iter()
            .any(|x| x.group_id.eq_ignore_ascii_case(group_id.trim()))
    });
    if !in_rules {
        return Err("group is not in the role rules".into());
    }
    if let Some(px) = cfg.population.id_prefix.as_deref()
        && !employee_id.trim().starts_with(px)
    {
        return Err(format!(
            "employee numbers in this staff category start with {px} (use the number as shown in the report)"
        ));
    }
    Ok(())
}

pub fn remove_exception(dir: &Path, id: &str) -> Result<Exception, String> {
    let mut x = load_exceptions(dir)?;
    let pos = x
        .items
        .iter()
        .position(|e| e.id == id)
        .ok_or_else(|| format!("no exception with id {id}"))?;
    let removed = x.items.remove(pos);
    save_exceptions(dir, &x)?;
    Ok(removed)
}

pub fn now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}
