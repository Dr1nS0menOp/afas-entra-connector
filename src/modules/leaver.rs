// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The afas-entra-sync Authors
//! Leavers: the day after the end date, sign out everywhere (revoke sessions) and
//! set an automatic reply. Disabling the account itself is done by provisioning;
//! group removal (and so licence removal) by the roles module.
//!
//! Converting the mailbox to a shared mailbox has no Microsoft Graph API; use the
//! webhook's leaver event to create that task in your ITSM tool.

use super::records::{AccessEntry, append_access, now};
use super::settings::LeaverConfig;
use super::{Action, Ctx, Found, ModuleReport, ModuleState, Person, match_users, with_graph};
use crate::graph::{GResult, Graph, seg};
use chrono::NaiveDate;
use reqwest::Method;
use serde_json::json;
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaverItem {
    pub employee_id: String,
    pub user_id: String,
    pub upn: String,
    pub end_date: NaiveDate,
    pub reply: Option<String>,
}

pub fn is_recent_leaver(p: &Person, grace: u32, today: NaiveDate) -> Option<NaiveDate> {
    let s = &p.snap;
    let end = s.end_date?;
    if s.active || s.start_date > today || end >= today {
        return None;
    }
    let age = (today - end).num_days();
    (age >= 1 && age <= i64::from(grace)).then_some(end)
}

/// The automatic reply for a leaver. A template that names the manager is only used when
/// the manager is known (name and email); otherwise `auto_reply_no_manager`, or no reply
/// at all (`Err` says why), so nobody gets "Please contact  ()".
pub fn reply_text(
    cfg: &LeaverConfig,
    p: &Person,
    manager: Option<&Person>,
) -> Option<Result<String, String>> {
    let t = cfg.auto_reply.as_ref()?;
    let names_manager = t.contains("{manager_name}") || t.contains("{manager_email}");
    let mgr = manager.filter(|m| m.snap.email.is_some() && !m.snap.display_name.is_empty());
    let text = match (names_manager, mgr) {
        (true, None) => match &cfg.auto_reply_no_manager {
            Some(alt) => alt.replace("{display_name}", &p.snap.display_name),
            None => {
                return Some(Err(
                    "no manager with an email address is known, so no automatic reply was set (set leaver.auto_reply_no_manager for this case)".into(),
                ));
            }
        },
        (_, m) => t
            .replace("{display_name}", &p.snap.display_name)
            .replace(
                "{manager_name}",
                m.map_or("", |m| m.snap.display_name.as_str()),
            )
            .replace(
                "{manager_email}",
                m.and_then(|m| m.snap.email.as_deref()).unwrap_or(""),
            ),
    };
    Some(Ok(text))
}

/// Days after the end date after which an account that is still enabled in Entra is
/// reported: provisioning should have disabled it long before.
pub const STILL_ENABLED_AFTER_DAYS: i64 = 2;

/// `(items, notes, pending)`. Sessions are only revoked once the account is disabled in
/// Entra: revoked earlier, the person could simply sign in again while the disable is still
/// on its way (provisioning plus Connect Sync can take up to about 90 minutes).
pub fn plan(
    cfg: &LeaverConfig,
    people: &[Person],
    found: &HashMap<String, Found>,
    state: &ModuleState,
    today: NaiveDate,
) -> (Vec<LeaverItem>, Vec<String>, Vec<String>) {
    let by_emp: HashMap<&str, &Person> =
        people.iter().map(|p| (p.employee_id.as_str(), p)).collect();
    let mut items = Vec::new();
    let mut notes = Vec::new();
    let mut pending = Vec::new();
    for p in people {
        let Some(end) = is_recent_leaver(p, cfg.grace_days, today) else {
            continue;
        };
        if state.leaver_done.get(&p.employee_id) == Some(&end) {
            continue;
        }
        let u = match found.get(&p.employee_id) {
            Some(Found::User(u)) => u,
            Some(Found::Conflict(why)) => {
                notes.push(format!(
                    "{}: departing employee (leaver) skipped, {why}",
                    p.employee_id
                ));
                continue;
            }
            _ => {
                notes.push(format!(
                    "{}: departing employee (leaver) has no account in Entra; nothing to do",
                    p.employee_id
                ));
                continue;
            }
        };
        if u.enabled {
            let days = (today - end).num_days();
            if days >= STILL_ENABLED_AFTER_DAYS {
                notes.push(format!(
                    "{}: account {} is still enabled in Entra {days} days after the end date ({end}); provisioning has not disabled it. Check the provisioning logs (check-logs) and the account in AD",
                    p.employee_id, u.upn
                ));
            } else {
                pending.push(format!(
                    "{}: waiting until the account is disabled in Entra before signing out everywhere",
                    p.employee_id
                ));
            }
            continue;
        }
        let manager = p
            .snap
            .manager_id
            .as_deref()
            .and_then(|m| by_emp.get(m))
            .copied();
        let reply = match reply_text(cfg, p, manager) {
            None => None,
            Some(Ok(t)) => Some(t),
            Some(Err(why)) => {
                notes.push(format!("{}: {why}", p.employee_id));
                None
            }
        };
        if reply.is_none() && !cfg.revoke_sessions {
            continue;
        }
        items.push(LeaverItem {
            employee_id: p.employee_id.clone(),
            user_id: u.id.clone(),
            upn: u.upn.clone(),
            end_date: end,
            reply,
        });
    }
    (items, notes, pending)
}

/// Exchange shows automatic replies as HTML: escape the text (names come from AFAS)
/// and keep its line breaks.
pub fn reply_html(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 16);
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            '\n' => out.push_str("<br>"),
            '\r' => {}
            c => out.push(c),
        }
    }
    out
}

fn act(g: &Graph<'_>, cfg: &LeaverConfig, it: &LeaverItem) -> GResult<Vec<String>> {
    let uid = seg(&it.user_id)?;
    let mut done = Vec::new();
    if cfg.revoke_sessions {
        g.call(
            Method::POST,
            &format!("users/{uid}/revokeSignInSessions"),
            None,
        )?;
        done.push("signed out everywhere".to_string());
    }
    if let Some(msg) = &it.reply {
        let html = reply_html(msg);
        let body = json!({ "automaticRepliesSetting": {
            "status": "alwaysEnabled",
            "internalReplyMessage": html,
            "externalReplyMessage": if cfg.auto_reply_external { html.as_str() } else { "" },
            "externalAudience": if cfg.auto_reply_external { "all" } else { "none" },
        }});
        match g.call(
            Method::PATCH,
            &format!("users/{uid}/mailboxSettings"),
            Some(&body),
        ) {
            Ok(_) => done.push("automatic reply set".into()),
            Err(e) if e.status == Some(404) || e.code.contains("MailboxNotEnabled") => {
                done.push("no mailbox, no automatic reply".into());
            }
            Err(e) => return Err(e),
        }
    }
    Ok(done)
}

pub fn run(ctx: &Ctx<'_>, cfg: &LeaverConfig, state: &mut ModuleState) -> ModuleReport {
    if ctx.apply {
        let horizon = ctx.today - chrono::Days::new(400);
        state.leaver_done.retain(|_, d| *d >= horizon);
    }
    let res = with_graph(ctx, &cfg.identity(), |g| -> Result<ModuleReport, String> {
        let users = ctx.users(g).map_err(|e| format!("users: {e}"))?;
        let found = match_users(ctx.people, &users);
        let (items, notes, pending) = plan(cfg, ctx.people, &found, state, ctx.today);
        let mut rep = ModuleReport {
            notes,
            pending,
            planned: items
                .iter()
                .map(|it| Action {
                    action: "leaver_actions".into(),
                    employee_id: Some(it.employee_id.clone()),
                    upn: Some(it.upn.clone()),
                    target: None,
                    detail: Some(format!("end date {}", it.end_date)),
                })
                .collect(),
            ..Default::default()
        };
        if items.len() > cfg.max_per_run as usize {
            rep.violations.push(format!(
                "{} departing employees (leavers) planned, maximum is {}; nothing done",
                items.len(),
                cfg.max_per_run
            ));
        } else if ctx.apply {
            for it in &items {
                let r = act(g, cfg, it);
                let logged = append_access(
                    ctx.state_dir,
                    &AccessEntry {
                        utc: now(),
                        module: "leaver".into(),
                        action: "leaver_actions".into(),
                        employee_id: Some(it.employee_id.clone()),
                        upn: Some(it.upn.clone()),
                        target: None,
                        ok: r.is_ok(),
                        detail: Some(match &r {
                            Ok(d) => d.join(", "),
                            Err(e) => e.to_string(),
                        }),
                        actor: ctx.actor.into(),
                    },
                );
                super::note_log_failure(&mut rep, logged);
                match r {
                    Ok(_) => {
                        state
                            .leaver_done
                            .insert(it.employee_id.clone(), it.end_date);
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
