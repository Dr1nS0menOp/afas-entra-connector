// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The afas-entra-sync Authors
//! Joiners: a Temporary Access Pass (TAP) for the first sign-in, valid from the
//! start date, mailed to the manager or a fixed address (e.g. the service desk).
//!
//! The pass itself is never logged or stored. One pass per employee per start
//! date. If the mail cannot be sent, the pass is deleted again so it does not
//! linger unknown; the next run tries again.

use super::records::{AccessEntry, append_access, now};
use super::settings::{DeliverTo, JoinerConfig};
use super::{Action, Ctx, Found, ModuleReport, ModuleState, Person, match_users, with_graph};
use crate::graph::{GResult, Graph, GraphError, seg};
use chrono::{NaiveDate, TimeZone};
use reqwest::Method;
use serde_json::json;
use std::collections::HashMap;

/// Days after the start date during which a missing pass is still issued.
const GRACE_DAYS: u64 = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TapItem {
    pub employee_id: String,
    pub user_id: String,
    pub upn: String,
    pub display_name: String,
    pub start_date: NaiveDate,
    pub to: String,
}

pub fn in_window(cfg: &JoinerConfig, start: NaiveDate, today: NaiveDate) -> bool {
    let from = start
        .checked_sub_days(chrono::Days::new(u64::from(cfg.days_before_start)))
        .unwrap_or(NaiveDate::MIN);
    let until = start
        .checked_add_days(chrono::Days::new(GRACE_DAYS))
        .unwrap_or(NaiveDate::MAX);
    today >= from && today <= until
}

/// Who gets a pass this run, and where it goes.
pub fn plan(
    cfg: &JoinerConfig,
    people: &[Person],
    found: &HashMap<String, Found>,
    state: &ModuleState,
    today: NaiveDate,
) -> (Vec<TapItem>, Vec<String>) {
    let by_emp: HashMap<&str, &Person> =
        people.iter().map(|p| (p.employee_id.as_str(), p)).collect();
    let mut items = Vec::new();
    let mut notes = Vec::new();
    for p in people {
        let s = &p.snap;
        if !in_window(cfg, s.start_date, today)
            || s.end_date.is_some_and(|e| e < today)
            || state.tap_issued.get(&p.employee_id) == Some(&s.start_date)
        {
            continue;
        }
        let u = match found.get(&p.employee_id) {
            Some(Found::User(u)) => u,
            Some(Found::Conflict(why)) => {
                notes.push(format!(
                    "{}: new hire (joiner) gets no first sign-in code, {why}",
                    p.employee_id
                ));
                continue;
            }
            _ => {
                notes.push(format!(
                    "{}: new hire (joiner) gets no first sign-in code yet, the account is not in Entra yet (retried next run)",
                    p.employee_id
                ));
                continue;
            }
        };
        let manager_mail = || -> Option<String> {
            let m = s.manager_id.as_deref()?;
            let mp = by_emp.get(m)?;
            // Never to a manager who has left: that mailbox may be shared with others by now.
            if !mp.snap.active {
                return None;
            }
            mp.snap.email.clone().or_else(|| match found.get(m) {
                Some(Found::User(mu)) if mu.enabled => mu.mail.clone(),
                _ => None,
            })
        };
        let to = match cfg.deliver_to {
            DeliverTo::Fixed => cfg.fixed_address.clone(),
            DeliverTo::Manager => manager_mail().or_else(|| cfg.fixed_address.clone()),
        };
        let Some(to) = to else {
            notes.push(format!(
                "{}: new hire (joiner) gets no first sign-in code, the manager has no email address and no fixed_address is set",
                p.employee_id
            ));
            continue;
        };
        items.push(TapItem {
            employee_id: p.employee_id.clone(),
            user_id: u.id.clone(),
            upn: u.upn.clone(),
            display_name: s.display_name.clone(),
            start_date: s.start_date,
            to,
        });
    }
    (items, notes)
}

/// Error code for "the user already has a pass" (a note, not a failure).
pub const EXISTING_PASS: &str = "ExistingTemporaryAccessPass";

/// Start of validity in UTC: `hour` local time on `date`. When that hour does not exist
/// (clocks move forward), the first existing hour after it; when it exists twice, the
/// first. Never earlier than asked.
pub fn valid_from_utc(
    tz: chrono_tz::Tz,
    date: NaiveDate,
    hour: u32,
) -> Option<chrono::DateTime<chrono::Utc>> {
    (hour..=23).chain(std::iter::once(24)).find_map(|h| {
        let local = if h == 24 {
            date.succ_opt()?.and_hms_opt(0, 0, 0)?
        } else {
            date.and_hms_opt(h, 0, 0)?
        };
        tz.from_local_datetime(&local)
            .earliest()
            .map(|d| d.with_timezone(&chrono::Utc))
    })
}

fn remove_all_passes(g: &Graph<'_>, taps: &str) {
    if let Ok(list) = g.get_all(taps) {
        for m in list {
            if let Some(Ok(mid)) = m["id"].as_str().map(seg) {
                let _ = g.call(Method::DELETE, &format!("{taps}/{mid}"), None);
            }
        }
    }
}

pub fn render(t: &str, it: &TapItem, tap: &str, from: &str, until: &str) -> String {
    t.replace("{display_name}", &it.display_name)
        .replace("{upn}", &it.upn)
        .replace("{start_date}", &it.start_date.to_string())
        .replace("{valid_from}", from)
        .replace("{valid_until}", until)
        .replace("{tap}", tap)
}

/// Mailbox address as a URL path segment.
pub fn mailbox(addr: &str) -> GResult<&str> {
    if super::settings::is_email(addr) && !addr.contains(['/', '?', '#', '%', '\\']) {
        Ok(addr)
    } else {
        Err(GraphError {
            status: None,
            code: String::new(),
            message: format!("refused mailbox address '{addr}'"),
        })
    }
}

fn issue(g: &Graph<'_>, ctx: &Ctx<'_>, cfg: &JoinerConfig, it: &TapItem) -> GResult<()> {
    let tz = ctx.cfg.tz();
    let start_local =
        valid_from_utc(tz, it.start_date, cfg.start_hour).ok_or_else(|| GraphError {
            status: None,
            code: String::new(),
            message: format!(
                "no valid start time for {} {}:00",
                it.start_date, cfg.start_hour
            ),
        })?;
    let now_utc = chrono::Utc::now();
    let valid_from = if start_local > now_utc {
        start_local
    } else {
        now_utc
    };
    let mut body = json!({
        "lifetimeInMinutes": cfg.lifetime_minutes,
        "isUsableOnce": cfg.usable_once,
    });
    if valid_from > now_utc {
        body["startDateTime"] =
            json!(valid_from.to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
    }
    let taps = format!(
        "users/{}/authentication/temporaryAccessPassMethods",
        seg(&it.user_id)?
    );
    // A user can have only one pass. An expired or used one is of no use to anyone and
    // is removed (e.g. from an earlier employment). A usable or future one was made by
    // someone else (service desk) or by an earlier attempt: never replace it silently.
    let mut existing = Vec::new();
    for m in g.get_all(&taps)? {
        let spent = m["isUsable"] == json!(false)
            && matches!(
                m["methodUsabilityReason"].as_str(),
                Some("Expired" | "OneTimeUsed")
            );
        match (spent, m["id"].as_str().map(seg)) {
            (true, Some(Ok(mid))) => {
                g.call(Method::DELETE, &format!("{taps}/{mid}"), None)?;
            }
            _ => existing.push(m),
        }
    }
    if !existing.is_empty() {
        return Err(GraphError {
            status: None,
            code: EXISTING_PASS.into(),
            message: "already has a Temporary Access Pass; not replaced (delete it in Entra to have a new one sent)".into(),
        });
    }
    let (_, v) = match g.call(Method::POST, &taps, Some(&body)) {
        Ok(x) => x,
        Err(e) => {
            if e.outcome_unknown() {
                // Graph may have created it anyway; nobody knows that pass, so remove it.
                remove_all_passes(g, &taps);
            }
            return Err(e);
        }
    };
    let tap = v["temporaryAccessPass"].as_str().unwrap_or("").to_string();
    let method_id = v["id"].as_str().unwrap_or("").to_string();
    if tap.is_empty() {
        return Err(GraphError {
            status: None,
            code: String::new(),
            message: "no temporaryAccessPass in the response".into(),
        });
    }
    let fmt = |d: chrono::DateTime<chrono::Utc>| {
        d.with_timezone(&tz).format("%Y-%m-%d %H:%M").to_string()
    };
    let until = valid_from + chrono::Duration::minutes(i64::from(cfg.lifetime_minutes));
    let mail = json!({
        "message": {
            "subject": render(&cfg.subject, it, "", &fmt(valid_from), &fmt(until)),
            "body": { "contentType": "Text", "content": render(&cfg.body, it, &tap, &fmt(valid_from), &fmt(until)) },
            "toRecipients": [ { "emailAddress": { "address": it.to } } ],
        },
        "saveToSentItems": false,
    });
    let sent = g.call(
        Method::POST,
        &format!("users/{}/sendMail", mailbox(&cfg.sender)?),
        Some(&mail),
    );
    if let Err(e) = sent {
        // Nobody knows this pass: remove it so it cannot be misused, retry next run.
        if let Ok(mid) = seg(&method_id) {
            let _ = g.call(
                Method::DELETE,
                &format!(
                    "users/{}/authentication/temporaryAccessPassMethods/{mid}",
                    seg(&it.user_id)?
                ),
                None,
            );
        }
        return Err(GraphError {
            message: format!(
                "mail not sent, first sign-in code (Temporary Access Pass) removed again: {}",
                e.message
            ),
            ..e
        });
    }
    Ok(())
}

pub fn run(ctx: &Ctx<'_>, cfg: &JoinerConfig, state: &mut ModuleState) -> ModuleReport {
    // Forget passes for start dates long gone.
    let horizon = ctx.today - chrono::Days::new(60);
    if ctx.apply {
        state.tap_issued.retain(|_, d| *d >= horizon);
        state.tap_existing_noted.retain(|_, d| *d >= horizon);
    }
    let res = with_graph(ctx, &cfg.identity(), |g| -> Result<ModuleReport, String> {
        let users = ctx.users(g).map_err(|e| format!("users: {e}"))?;
        let found = match_users(ctx.people, &users);
        let (items, notes) = plan(cfg, ctx.people, &found, state, ctx.today);
        let mut rep = ModuleReport {
            notes,
            planned: items
                .iter()
                .map(|it| Action {
                    action: "issue_temporary_access_pass".into(),
                    employee_id: Some(it.employee_id.clone()),
                    upn: Some(it.upn.clone()),
                    target: Some(it.to.clone()),
                    detail: Some(format!("start {}", it.start_date)),
                })
                .collect(),
            ..Default::default()
        };
        if items.len() > cfg.max_per_run as usize {
            rep.violations.push(format!(
                "{} first sign-in codes planned, maximum is {}; none sent",
                items.len(),
                cfg.max_per_run
            ));
        } else if ctx.apply {
            for it in &items {
                let r = issue(g, ctx, cfg, it);
                if let Err(e) = &r
                    && e.code == EXISTING_PASS
                {
                    // Said once per start date; checked again every run, so deleting the
                    // pass in Entra still makes the tool send a new one.
                    if state.tap_existing_noted.get(&it.employee_id) != Some(&it.start_date) {
                        rep.notes.push(format!("{}: {}", it.employee_id, e.message));
                        state
                            .tap_existing_noted
                            .insert(it.employee_id.clone(), it.start_date);
                    } else {
                        rep.pending.push(format!(
                            "{}: still has a Temporary Access Pass made elsewhere",
                            it.employee_id
                        ));
                    }
                    continue;
                }
                let logged = append_access(
                    ctx.state_dir,
                    &AccessEntry {
                        utc: now(),
                        module: "joiner".into(),
                        action: "issue_temporary_access_pass".into(),
                        employee_id: Some(it.employee_id.clone()),
                        upn: Some(it.upn.clone()),
                        target: Some(it.to.clone()),
                        ok: r.is_ok(),
                        detail: r.as_ref().err().map(ToString::to_string),
                        actor: ctx.actor.into(),
                    },
                );
                super::note_log_failure(&mut rep, logged);
                match r {
                    Ok(()) => {
                        state
                            .tap_issued
                            .insert(it.employee_id.clone(), it.start_date);
                        rep.applied += 1;
                    }
                    Err(e) => rep.failed.push(format!("{}: {e}", it.upn)),
                }
            }
        }
        rep.graph_calls = g.calls.get();
        Ok(rep)
    });
    match res {
        Ok(Ok(r)) => r,
        Ok(Err(e)) | Err(e) => ModuleReport::errored(e),
    }
}
