// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The afas-entra-sync Authors
//! Webhook: joiner, mover and leaver events as signed JSON, for an ITSM tool,
//! Power Automate or anything that accepts HTTPS POSTs.
//!
//! Events are detected by comparing with the previous applied run (the first run
//! only records a baseline), kept in an outbox and retried until delivered. Each
//! event has a unique id for de-duplication. Signature header:
//! `X-AfasEntraSync-Signature: sha256=<hex HMAC-SHA256 of "<timestamp>.<body>">`.

use super::settings::{EventKind, WebhookConfig};
use super::{Action, Ctx, ModuleReport, ModuleState, Person, Snapshot};
use crate::http::{MAX_SMALL_BODY, build_client, read_capped, snippet};
use chrono::NaiveDate;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const MAX_OUTBOX: usize = 10_000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Event {
    pub id: String,
    pub event: EventKind,
    pub created_utc: String,
    pub employee_id: String,
    pub rehire: bool,
    pub employee: Snapshot,
    /// Mover: field → [old, new].
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub changes: BTreeMap<String, [Option<String>; 2]>,
    #[serde(default)]
    pub attempts: u32,
}

fn fields(s: &Snapshot) -> [(&'static str, Option<String>); 10] {
    [
        ("upn", Some(s.upn.clone())),
        ("display_name", Some(s.display_name.clone())),
        ("department", s.department.clone()),
        ("job_title", s.job_title.clone()),
        ("job_profile", s.job_profile.clone()),
        ("office", s.office.clone()),
        ("company", s.company.clone()),
        ("employee_type", s.employee_type.clone()),
        ("cost_center", s.cost_center.clone()),
        ("manager_id", s.manager_id.clone()),
    ]
}

fn event(
    kind: EventKind,
    p: &Person,
    rehire: bool,
    changes: BTreeMap<String, [Option<String>; 2]>,
) -> Event {
    Event {
        id: uuid::Uuid::new_v4().to_string(),
        event: kind,
        created_utc: super::records::now(),
        employee_id: p.employee_id.clone(),
        rehire,
        employee: p.snap.clone(),
        changes,
        attempts: 0,
    }
}

/// Events since the previous applied run. No previous run = baseline, no events.
pub fn detect(
    people: &[Person],
    prev: &BTreeMap<String, Snapshot>,
    today: NaiveDate,
) -> Vec<Event> {
    if prev.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for p in people {
        let now = &p.snap;
        let left_now = !now.active && now.start_date <= today;
        match prev.get(&p.employee_id) {
            None => {
                if !left_now {
                    out.push(event(EventKind::Joiner, p, false, BTreeMap::new()));
                }
            }
            Some(before) => {
                let left_before = !before.active && before.start_date <= today;
                if !left_before && left_now {
                    out.push(event(EventKind::Leaver, p, false, BTreeMap::new()));
                } else if left_before && !left_now {
                    out.push(event(EventKind::Joiner, p, true, BTreeMap::new()));
                } else if !left_now {
                    let changes: BTreeMap<String, [Option<String>; 2]> = fields(before)
                        .into_iter()
                        .zip(fields(now))
                        .filter(|((_, a), (_, b))| a != b)
                        .map(|((k, a), (_, b))| (k.to_string(), [a, b]))
                        .collect();
                    if !changes.is_empty() {
                        out.push(event(EventKind::Mover, p, false, changes));
                    }
                }
            }
        }
    }
    out
}

/// HMAC-SHA256 (RFC 2104), computed by aws-lc (the cryptographic library rustls uses);
/// nothing cryptographic is implemented here.
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    use aws_lc_rs::hmac;
    let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), msg);
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn secret(cfg: &WebhookConfig) -> Result<Vec<u8>, String> {
    let s = if let Some(var) = &cfg.secret_env {
        std::env::var(var)
            .map_err(|_| format!("environment variable {var} (webhook secret) is not set"))?
    } else if let Some(f) = &cfg.secret_file {
        crate::state::check_private_file(f, "webhook secret file").map_err(|e| e.to_string())?;
        std::fs::read_to_string(f).map_err(|e| format!("webhook secret: {e}"))?
    } else {
        return Err("no webhook secret configured".into());
    };
    let s = s.trim();
    if s.len() < 16 {
        return Err("webhook secret must be at least 16 characters".into());
    }
    Ok(s.as_bytes().to_vec())
}

pub fn run(
    ctx: &Ctx<'_>,
    cfg: &WebhookConfig,
    state: &mut ModuleState,
    events: Vec<Event>,
) -> ModuleReport {
    let new: Vec<Event> = events
        .into_iter()
        .filter(|e| cfg.events.contains(&e.event))
        .collect();
    let mut rep = ModuleReport::default();
    let describe = |e: &Event| Action {
        action: format!(
            "event_{}",
            serde_json::to_value(e.event)
                .ok()
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_default()
        ),
        employee_id: Some(e.employee_id.clone()),
        upn: Some(e.employee.upn.clone()),
        target: None,
        detail: (!e.changes.is_empty())
            .then(|| e.changes.keys().cloned().collect::<Vec<_>>().join(", ")),
    };
    if !ctx.apply {
        rep.planned = state
            .outbox
            .iter()
            .chain(new.iter())
            .map(describe)
            .collect();
        return rep;
    }
    state.outbox.extend(new);
    if state.outbox.len() > MAX_OUTBOX {
        let drop = state.outbox.len() - MAX_OUTBOX;
        state.outbox.drain(..drop);
        rep.notes.push(format!(
            "send queue (outbox) full: {drop} oldest events dropped"
        ));
    }
    rep.planned = state.outbox.iter().map(describe).collect();
    if state.outbox.is_empty() {
        return rep;
    }
    let key = match secret(cfg) {
        Ok(k) => k,
        Err(e) => {
            rep.error = Some(e);
            return rep;
        }
    };
    let client = match build_client(cfg.timeout_secs, ctx.use_system_proxy, &ctx.cfg.tls) {
        Ok(c) => c,
        Err(e) => {
            rep.error = Some(e);
            return rep;
        }
    };
    let mut kept = Vec::new();
    let mut sent_this_run = 0u32;
    for mut ev in std::mem::take(&mut state.outbox) {
        if sent_this_run >= cfg.max_per_run || !rep.failed.is_empty() {
            // Keep order: once one fails, the rest waits for the next run.
            kept.push(ev);
            continue;
        }
        let mut payload = serde_json::to_value(&ev).unwrap_or_default();
        if let Some(o) = payload.as_object_mut() {
            o.remove("attempts");
        }
        let body = serde_json::to_vec(&payload).unwrap_or_default();
        let ts = chrono::Utc::now().timestamp().to_string();
        let mut signed = ts.clone().into_bytes();
        signed.push(b'.');
        signed.extend_from_slice(&body);
        let sig = format!("sha256={}", hex(&hmac_sha256(&key, &signed)));
        let r = client
            .post(&cfg.url)
            .header("Content-Type", "application/json")
            .header(
                "X-AfasEntraSync-Event",
                payload["event"].as_str().unwrap_or(""),
            )
            .header("X-AfasEntraSync-Delivery", ev.id.as_str())
            .header("X-AfasEntraSync-Timestamp", ts.as_str())
            .header("X-AfasEntraSync-Signature", sig)
            .body(body)
            .send();
        sent_this_run += 1;
        match r {
            Ok(resp) if resp.status().is_success() => rep.applied += 1,
            Ok(resp) => {
                let status = resp.status();
                let text = read_capped(resp, MAX_SMALL_BODY).unwrap_or_default();
                ev.attempts += 1;
                rep.failed.push(format!(
                    "event {} ({}): HTTP {status} {}",
                    ev.id,
                    ev.employee_id,
                    snippet(&text, 200)
                ));
                kept.push(ev);
            }
            Err(e) => {
                ev.attempts += 1;
                rep.failed
                    .push(format!("event {} ({}): {e}", ev.id, ev.employee_id));
                kept.push(ev);
            }
        }
    }
    if !kept.is_empty() {
        rep.notes.push(format!(
            "{} events wait in the send queue (outbox) for the next run",
            kept.len()
        ));
    }
    state.outbox = kept;
    rep
}
