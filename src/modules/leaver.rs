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
use crate::graph::{GResult, Graph, list_users, seg};
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

pub fn plan(
    cfg: &LeaverConfig,
    people: &[Person],
    found: &HashMap<String, Found>,
    state: &ModuleState,
    today: NaiveDate,
) -> (Vec<LeaverItem>, Vec<String>) {
    let by_emp: HashMap<&str, &Person> =
        people.iter().map(|p| (p.employee_id.as_str(), p)).collect();
    let mut items = Vec::new();
    let mut notes = Vec::new();
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
                notes.push(format!("{}: leaver actions skipped, {why}", p.employee_id));
                continue;
            }
            _ => {
                notes.push(format!(
                    "{}: leaver has no account in Entra; nothing to do",
                    p.employee_id
                ));
                continue;
            }
        };
        let reply = cfg.auto_reply.as_ref().map(|t| {
            let mgr = p.snap.manager_id.as_deref().and_then(|m| by_emp.get(m));
            t.replace("{display_name}", &p.snap.display_name)
                .replace(
                    "{manager_name}",
                    mgr.map_or("", |m| m.snap.display_name.as_str()),
                )
                .replace(
                    "{manager_email}",
                    mgr.and_then(|m| m.snap.email.as_deref()).unwrap_or(""),
                )
        });
        items.push(LeaverItem {
            employee_id: p.employee_id.clone(),
            user_id: u.id.clone(),
            upn: u.upn.clone(),
            end_date: end,
            reply,
        });
    }
    (items, notes)
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
        done.push("sessions revoked".to_string());
    }
    if let Some(msg) = &it.reply {
        let body = json!({ "automaticRepliesSetting": {
            "status": "alwaysEnabled",
            "internalReplyMessage": msg,
            "externalReplyMessage": if cfg.auto_reply_external { msg.as_str() } else { "" },
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
        let users = list_users(g).map_err(|e| format!("users: {e}"))?;
        let found = match_users(ctx.people, &users);
        let (items, notes) = plan(cfg, ctx.people, &found, state, ctx.today);
        let mut rep = ModuleReport {
            notes,
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
                "{} leavers planned, maximum is {}; nothing done",
                items.len(),
                cfg.max_per_run
            ));
        } else if ctx.apply {
            for it in &items {
                let r = act(g, cfg, it);
                let _ = append_access(
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
