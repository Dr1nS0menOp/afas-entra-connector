// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The afas-entra-sync Authors
//! One message, four forms: an HTML email (with the full log and report attached), a
//! Microsoft Teams Adaptive Card, a Slack Block Kit message and plain JSON for webhooks.
//!
//! Every form tells the same story in the same order: the verdict, what it means, the
//! facts of the run, then each finding (what happened, what it means, why the tool leaves
//! it to people, what to do, who is involved) and finally the log.

use super::findings::{Audience, Finding, Severity, Table};
use crate::web::esc;
use serde::Serialize;
use serde_json::{Value, json};
use std::fmt::Write as _;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Event {
    /// The run failed or stopped.
    Failure,
    /// Things need attention.
    Attention,
    /// Works again after a failure.
    Recovered,
    /// The points of attention are gone.
    AllClear,
    /// A successful run (only with `on = ["success"]`).
    Success,
    /// `notify-test`.
    Test,
}

impl Event {
    pub fn label(self) -> &'static str {
        match self {
            Event::Failure => "Failed",
            Event::Attention => "Needs attention",
            Event::Recovered => "Recovered",
            Event::AllClear => "All clear",
            Event::Success => "Succeeded",
            Event::Test => "Test message",
        }
    }

    fn color(self) -> &'static str {
        match self {
            Event::Failure => "#b0261e",
            Event::Attention => "#975400",
            Event::Recovered | Event::AllClear => "#1d7546",
            Event::Success | Event::Test => "#0b6b70",
        }
    }

    fn teams_style(self) -> &'static str {
        match self {
            Event::Failure => "attention",
            Event::Attention => "warning",
            Event::Recovered | Event::AllClear => "good",
            Event::Success | Event::Test => "accent",
        }
    }

    fn slack_emoji(self) -> &'static str {
        match self {
            Event::Failure => ":red_circle:",
            Event::Attention => ":large_orange_circle:",
            Event::Recovered | Event::AllClear => ":large_green_circle:",
            Event::Success | Event::Test => ":large_blue_circle:",
        }
    }
}

fn severity_label(s: Severity) -> &'static str {
    match s {
        Severity::Failure => "Run failed",
        Severity::Action => "Action needed",
        Severity::Info => "Good to know",
    }
}

fn severity_color(s: Severity) -> &'static str {
    match s {
        Severity::Failure => "#b0261e",
        Severity::Action => "#975400",
        Severity::Info => "#0b6b70",
    }
}

fn audience_label(a: &[Audience]) -> String {
    let v: Vec<&str> = a.iter().map(|x| x.label()).collect();
    format!("For {}", v.join(" and "))
}

/// Everything a channel needs to show one notification.
#[derive(Debug, Clone, Serialize)]
pub struct Message {
    pub id: String,
    pub event: Event,
    /// "Sync", "Test run", "Provisioning log check", "Test message".
    pub source: String,
    pub population: Option<String>,
    pub headline: String,
    pub lead: String,
    pub facts: Vec<(String, String)>,
    pub findings: Vec<Finding>,
    /// The full log of the run.
    pub log: Vec<String>,
    /// Where the log is on the server.
    pub log_path: Option<String>,
    /// The full report (as written to the state directory).
    pub report: Option<Value>,
    pub gui_url: Option<String>,
    pub host: String,
    /// The channel's name, for the footer.
    pub channel: String,
    pub repeat_hours: u32,
    pub created_utc: String,
}

impl Message {
    fn brand(&self) -> String {
        match &self.population {
            Some(p) => format!("AFAS → Entra · {p}"),
            None => "AFAS → Entra".into(),
        }
    }

    fn footer(&self) -> String {
        let mut s = format!(
            "Sent by afas-entra-sync {} on {} to the channel '{}' (configured under [notify] in the config file).",
            env!("CARGO_PKG_VERSION"),
            self.host,
            self.channel
        );
        if self.repeat_hours > 0 && self.event != Event::Test {
            let _ = write!(
                s,
                " Unchanged points are repeated at most once every {} hours.",
                self.repeat_hours
            );
        }
        s
    }

    fn log_tail(&self, n: usize) -> Vec<&str> {
        let start = self.log.len().saturating_sub(n);
        self.log[start..].iter().map(String::as_str).collect()
    }

    /// The only finding, already told by the headline and lead: not repeated in the card.
    fn is_lead(&self, f: &Finding) -> bool {
        self.findings.len() == 1 && f.title == self.headline
    }

    pub fn subject(&self) -> String {
        let s = format!(
            "[{}] {}: {}",
            self.brand(),
            self.event.label(),
            self.headline
        );
        truncate(&s, 180)
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut t: String = s.chars().take(max.saturating_sub(1)).collect();
    t.push('…');
    t
}

/// Text with `code` spans → HTML.
fn inline_html(s: &str) -> String {
    let mut out = String::new();
    for (i, part) in s.split('`').enumerate() {
        if i % 2 == 1 {
            let _ = write!(
                out,
                "<code style=\"font-family:Consolas,'SFMono-Regular',Menlo,monospace;font-size:13px;background:#eef2f4;border-radius:4px;padding:1px 5px\">{}</code>",
                esc(part)
            );
        } else {
            out.push_str(&esc(part));
        }
    }
    out
}

// ------------------------------------------------------------------ email

const FONT: &str = "'Segoe UI',Calibri,'Helvetica Neue',Arial,sans-serif";

fn email_table(t: &Table, max_rows: usize) -> String {
    let mut b = String::new();
    let _ = write!(
        b,
        "<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" style=\"border-collapse:collapse;margin:12px 0 4px;font-size:13.5px;border:1px solid #dbe3e8\">"
    );
    b.push_str("<tr>");
    for c in &t.columns {
        let _ = write!(
            b,
            "<th align=\"left\" style=\"padding:7px 10px;background:#f3f6f8;color:#566874;font-weight:600;font-size:12.5px;border-bottom:1px solid #dbe3e8\">{}</th>",
            esc(&c.label)
        );
    }
    b.push_str("</tr>");
    for (i, row) in t.rows.iter().take(max_rows).enumerate() {
        let bg = if i % 2 == 1 { "#fafbfc" } else { "#ffffff" };
        b.push_str("<tr>");
        for cell in row {
            let _ = write!(
                b,
                "<td valign=\"top\" style=\"padding:7px 10px;background:{bg};border-bottom:1px solid #edf1f3;color:#132430\">{}</td>",
                if cell.is_empty() {
                    "—".to_string()
                } else {
                    esc(cell)
                }
            );
        }
        b.push_str("</tr>");
    }
    b.push_str("</table>");
    if t.rows.len() > max_rows {
        let _ = write!(
            b,
            "<p style=\"margin:4px 0 0;font-size:13px;color:#566874\">And {} more: see the attached report.</p>",
            t.rows.len() - max_rows
        );
    }
    b
}

fn email_finding(f: &Finding, lead: bool) -> String {
    let color = severity_color(f.severity);
    let mut pills = String::new();
    if f.new {
        pills.push_str("<span style=\"display:inline-block;background:#0b6b70;color:#ffffff;font-size:11px;font-weight:700;letter-spacing:.06em;border-radius:999px;padding:2px 8px;margin-right:6px\">NEW</span>");
    }
    let _ = write!(
        pills,
        "<span style=\"display:inline-block;color:{color};font-size:12px;font-weight:700;letter-spacing:.04em;margin-right:10px\">{}</span><span style=\"display:inline-block;color:#566874;font-size:12px;font-weight:600\">{}</span>",
        severity_label(f.severity).to_uppercase(),
        esc(&audience_label(&f.audience))
    );
    let section = |title: &str, body: &str| -> String {
        if body.is_empty() {
            return String::new();
        }
        format!(
            "<p style=\"margin:12px 0 2px;font-size:12.5px;font-weight:700;color:#566874;letter-spacing:.02em\">{title}</p><p style=\"margin:0;font-size:14.5px;line-height:1.55;color:#132430\">{}</p>",
            inline_html(body)
        )
    };
    let mut todo = String::new();
    if !f.todo.is_empty() {
        todo.push_str("<p style=\"margin:12px 0 2px;font-size:12.5px;font-weight:700;color:#566874\">What to do</p><ol style=\"margin:2px 0 0;padding-left:22px;font-size:14.5px;line-height:1.55;color:#132430\">");
        for t in &f.todo {
            let _ = write!(todo, "<li style=\"margin:2px 0\">{}</li>", inline_html(t));
        }
        todo.push_str("</ol>");
    }
    format!(
        "<tr><td style=\"padding:8px 28px 10px\"><table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" style=\"border:1px solid #dbe3e8;border-left:4px solid {color};border-radius:8px\"><tr><td style=\"padding:16px 18px\">\
<p style=\"margin:0 0 6px\">{pills}</p>{}{}{}{}{todo}{}</td></tr></table></td></tr>",
        if lead {
            String::new()
        } else {
            format!(
                "<h2 style=\"margin:0;font-size:17px;line-height:1.35;color:#132430;font-family:{FONT}\">{}</h2>",
                esc(&f.title)
            )
        },
        section("What happened", &f.what),
        section("What this means", if lead { "" } else { &f.impact }),
        section("Why the tool does not fix this itself", &f.why),
        f.table
            .as_ref()
            .filter(|t| !t.rows.is_empty())
            .map(|t| email_table(t, 50))
            .unwrap_or_default()
    )
}

/// Subject and HTML body.
pub fn email(m: &Message) -> (String, String) {
    let color = m.event.color();
    let mut b = String::new();
    let _ = write!(
        b,
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta name=\"color-scheme\" content=\"light\"><title>{}</title></head>\
<body style=\"margin:0;padding:0;background:#e9eef1\"><div style=\"display:none;max-height:0;overflow:hidden\">{}</div>\
<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" style=\"background:#e9eef1\"><tr><td align=\"center\" style=\"padding:28px 12px\">\
<table role=\"presentation\" width=\"680\" cellpadding=\"0\" cellspacing=\"0\" style=\"width:100%;max-width:680px;background:#ffffff;border:1px solid #cfd8de;border-radius:12px;font-family:{FONT};color:#132430\">\
<tr><td style=\"height:6px;background:{color};border-radius:12px 12px 0 0;font-size:0;line-height:0\">&nbsp;</td></tr>\
<tr><td style=\"padding:24px 28px 4px\"><p style=\"margin:0;font-size:12px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:{color}\">● {} &nbsp;·&nbsp; <span style=\"color:#566874\">{}</span></p>\
<h1 style=\"margin:8px 0 10px;font-size:23px;line-height:1.3;font-weight:600;color:#132430\">{}</h1><p style=\"margin:0;font-size:15.5px;line-height:1.55;color:#33454f\">{}</p></td></tr>",
        esc(&m.subject()),
        esc(&m.lead),
        esc(m.event.label()),
        esc(&format!("{} · {}", m.brand(), m.source)),
        esc(&m.headline),
        inline_html(&m.lead)
    );
    if !m.facts.is_empty() {
        b.push_str("<tr><td style=\"padding:16px 28px 8px\"><table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\" style=\"font-size:14px;line-height:1.5\">");
        for (k, v) in &m.facts {
            let _ = write!(
                b,
                "<tr><td valign=\"top\" style=\"padding:2px 22px 2px 0;color:#566874;white-space:nowrap\">{}</td><td style=\"padding:2px 0;color:#132430\">{}</td></tr>",
                esc(k),
                inline_html(v)
            );
        }
        b.push_str("</table></td></tr>");
    }
    if let Some(u) = &m.gui_url {
        let _ = write!(
            b,
            "<tr><td style=\"padding:6px 28px 4px\"><a href=\"{}\" style=\"display:inline-block;background:#0b6b70;color:#ffffff;text-decoration:none;font-weight:600;font-size:14px;border-radius:6px;padding:9px 18px\">Open the admin GUI</a></td></tr>",
            esc(u)
        );
    }
    if !m.findings.is_empty() {
        let new = m.findings.iter().filter(|f| f.new).count();
        let _ = write!(
            b,
            "<tr><td style=\"padding:18px 28px 0\"><p style=\"margin:0;font-size:13px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:#566874\">{}{}</p></td></tr>",
            if m.findings.len() == 1 {
                "1 point".to_string()
            } else {
                format!("{} points", m.findings.len())
            },
            if new > 0 && new < m.findings.len() {
                format!(" · {new} new since the last message")
            } else {
                String::new()
            }
        );
        for f in &m.findings {
            b.push_str(&email_finding(f, m.is_lead(f)));
        }
    }
    if !m.log.is_empty() {
        let tail = m.log_tail(40);
        let _ = write!(
            b,
            "<tr><td style=\"padding:14px 28px 6px\"><p style=\"margin:0 0 6px;font-size:12.5px;font-weight:700;color:#566874\">LAST {} LINES OF THE LOG{}</p>\
<pre style=\"margin:0;background:#0e191f;color:#e3ecf0;font-family:Consolas,'SFMono-Regular',Menlo,monospace;font-size:12px;line-height:1.5;padding:12px 14px;border-radius:8px;white-space:pre-wrap;word-break:break-word\">{}</pre></td></tr>",
            tail.len(),
            if m.log.len() > tail.len() {
                format!(" (all {} lines are attached as run.log)", m.log.len())
            } else {
                " (also attached as run.log)".to_string()
            },
            esc(&tail.join("\n"))
        );
    }
    let _ = write!(
        b,
        "<tr><td style=\"padding:18px 28px 24px\"><p style=\"margin:0;font-size:12.5px;line-height:1.5;color:#566874\">{}{}</p></td></tr>\
</table></td></tr></table></body></html>",
        esc(&m.footer()),
        m.log_path
            .as_ref()
            .map(|p| format!(" The full log is also on the server: {}.", esc(p)))
            .unwrap_or_default()
    );
    (m.subject(), b)
}

// ------------------------------------------------------------------ Microsoft Teams

fn tb(text: &str) -> Value {
    json!({ "type": "TextBlock", "text": text, "wrap": true })
}

fn teams_table(t: &Table, max_rows: usize) -> Value {
    let cell = |s: &str, bold: bool| {
        json!({ "type": "TableCell", "items": [ {
            "type": "TextBlock", "text": if s.is_empty() { "—" } else { s }, "wrap": true,
            "size": "Small", "weight": if bold { "Bolder" } else { "Default" } } ] })
    };
    let mut rows = vec![json!({
        "type": "TableRow",
        "cells": t.columns.iter().map(|c| cell(&c.label, true)).collect::<Vec<_>>()
    })];
    for r in t.rows.iter().take(max_rows) {
        rows.push(json!({
            "type": "TableRow",
            "cells": r.iter().map(|c| cell(c, false)).collect::<Vec<_>>()
        }));
    }
    json!({
        "type": "Table",
        "gridStyle": "default",
        "firstRowAsHeader": true,
        "showGridLines": true,
        "columns": t.columns.iter().map(|_| json!({ "width": 1 })).collect::<Vec<_>>(),
        "rows": rows,
    })
}

fn teams_card(m: &Message, max_rows: usize, log_lines: usize) -> Value {
    let mut body = vec![json!({
        "type": "Container",
        "style": m.event.teams_style(),
        "bleed": true,
        "items": [
            { "type": "TextBlock", "text": format!("{} · {} · {}", m.event.label().to_uppercase(), m.brand(), m.source), "size": "Small", "weight": "Bolder", "wrap": true },
            { "type": "TextBlock", "text": m.headline, "size": "Large", "weight": "Bolder", "wrap": true },
        ]
    })];
    body.push(tb(&m.lead));
    if !m.facts.is_empty() {
        body.push(json!({
            "type": "FactSet",
            "facts": m.facts.iter().map(|(k, v)| json!({ "title": k, "value": v })).collect::<Vec<_>>()
        }));
    }
    for f in &m.findings {
        let lead = m.is_lead(f);
        let mut items = vec![
            json!({ "type": "TextBlock", "text": format!("{}{} · {}", if f.new { "NEW · " } else { "" }, severity_label(f.severity).to_uppercase(), audience_label(&f.audience)), "size": "Small", "weight": "Bolder", "color": match f.severity { Severity::Failure => "Attention", Severity::Action => "Warning", Severity::Info => "Accent" }, "wrap": true }),
        ];
        if !lead {
            items.push(json!({ "type": "TextBlock", "text": f.title, "weight": "Bolder", "size": "Medium", "wrap": true }));
        }
        if !f.what.is_empty() {
            items.push(tb(&f.what));
        }
        if !f.impact.is_empty() && !lead {
            items.push(tb(&format!("**What this means:** {}", f.impact)));
        }
        if !f.why.is_empty() {
            items.push(json!({ "type": "TextBlock", "text": format!("**Why the tool does not fix this itself:** {}", f.why), "wrap": true, "isSubtle": true }));
        }
        if !f.todo.is_empty() {
            let list: Vec<String> = f
                .todo
                .iter()
                .enumerate()
                .map(|(i, t)| format!("{}. {t}", i + 1))
                .collect();
            items.push(tb(&format!("**What to do**\n\n{}", list.join("\n"))));
        }
        if max_rows > 0
            && let Some(t) = f.table.as_ref().filter(|t| !t.rows.is_empty())
        {
            items.push(teams_table(t, max_rows));
            if t.rows.len() > max_rows {
                items.push(json!({ "type": "TextBlock", "text": format!("And {} more (see the email or the report on {}).", t.rows.len() - max_rows, m.host), "isSubtle": true, "size": "Small", "wrap": true }));
            }
        }
        body.push(
            json!({ "type": "Container", "separator": true, "spacing": "Large", "items": items }),
        );
    }
    let mut actions = Vec::new();
    if !m.log.is_empty() && log_lines > 0 {
        let tail = m.log_tail(log_lines);
        body.push(json!({
            "type": "Container", "id": "log", "isVisible": false, "separator": true,
            "items": [
                { "type": "TextBlock", "text": format!("Last {} lines of the log{}", tail.len(), m.log_path.as_ref().map(|p| format!(" (full log: {p} on {})", m.host)).unwrap_or_default()), "weight": "Bolder", "size": "Small", "wrap": true },
                { "type": "TextBlock", "text": tail.join("\n"), "fontType": "Monospace", "size": "Small", "wrap": true }
            ]
        }));
        actions.push(json!({ "type": "Action.ToggleVisibility", "title": "Show the log", "targetElements": ["log"] }));
    }
    if let Some(u) = &m.gui_url {
        actions.push(json!({ "type": "Action.OpenUrl", "title": "Open the admin GUI", "url": u }));
    }
    body.push(json!({ "type": "TextBlock", "text": m.footer(), "isSubtle": true, "size": "Small", "wrap": true, "separator": true }));
    json!({
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "contentUrl": null,
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.5",
                "msteams": { "width": "Full" },
                "fallbackText": format!("{}: {}", m.event.label(), m.headline),
                "body": body,
                "actions": actions,
            }
        }]
    })
}

/// Teams limits a message to about 28 KB: tables and the log shrink until it fits.
pub const TEAMS_MAX_BYTES: usize = 26_000;

pub fn teams(m: &Message) -> Value {
    for (rows, log) in [(15, 40), (8, 25), (4, 15), (0, 10), (0, 0)] {
        let v = teams_card(m, rows, log);
        if v.to_string().len() <= TEAMS_MAX_BYTES {
            return v;
        }
    }
    // Still too large (very many findings): only the first ones.
    let mut short = m.clone();
    short.findings.truncate(8);
    teams_card(&short, 0, 0)
}

// ------------------------------------------------------------------ Slack

/// Slack mrkdwn needs &, < and > escaped.
fn mrkdwn(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn section(text: &str) -> Value {
    json!({ "type": "section", "text": { "type": "mrkdwn", "text": truncate(text, 2900) } })
}

fn slack_table(t: &Table, max_rows: usize) -> String {
    let cols = t.columns.len();
    let mut width = vec![0usize; cols];
    let rows: Vec<&Vec<String>> = t.rows.iter().take(max_rows).collect();
    for (i, c) in t.columns.iter().enumerate() {
        width[i] = c.label.chars().count();
    }
    for r in &rows {
        for (i, c) in r.iter().enumerate().take(cols) {
            width[i] = width[i].max(c.chars().count().min(40));
        }
    }
    let line = |cells: Vec<&str>| -> String {
        cells
            .iter()
            .enumerate()
            .map(|(i, c)| {
                let c = truncate(c, 40);
                format!("{c:<w$}", w = width[i])
            })
            .collect::<Vec<_>>()
            .join("  ")
            .trim_end()
            .to_string()
    };
    let mut out = vec![line(t.columns.iter().map(|c| c.label.as_str()).collect())];
    for r in rows {
        out.push(line(
            r.iter()
                .map(|c| if c.is_empty() { "—" } else { c.as_str() })
                .collect(),
        ));
    }
    format!("```{}```", out.join("\n"))
}

pub fn slack(m: &Message) -> Value {
    let mut blocks = vec![
        json!({ "type": "header", "text": { "type": "plain_text", "emoji": true, "text": truncate(&format!("{} {} · {}", m.event.slack_emoji(), m.event.label(), m.brand()), 150) } }),
        section(&format!("*{}*\n{}", mrkdwn(&m.headline), mrkdwn(&m.lead))),
    ];
    if !m.facts.is_empty() {
        blocks.push(json!({
            "type": "section",
            "fields": m.facts.iter().take(10).map(|(k, v)| json!({ "type": "mrkdwn", "text": truncate(&format!("*{}*\n{}", mrkdwn(k), mrkdwn(v)), 1900) })).collect::<Vec<_>>()
        }));
    }
    for f in &m.findings {
        if blocks.len() >= 44 {
            blocks.push(section(&format!(
                "_And more points: see the email, the GUI or the report on {}._",
                mrkdwn(&m.host)
            )));
            break;
        }
        blocks.push(json!({ "type": "divider" }));
        let lead = m.is_lead(f);
        let mut t = format!(
            "{}{}_{} · {}_",
            if f.new { "`NEW` " } else { "" },
            if lead {
                String::new()
            } else {
                format!("*{}*\n", mrkdwn(&f.title))
            },
            severity_label(f.severity),
            audience_label(&f.audience)
        );
        if !f.what.is_empty() {
            let _ = write!(t, "\n{}", mrkdwn(&f.what));
        }
        if !f.impact.is_empty() && !lead {
            let _ = write!(t, "\n*What this means:* {}", mrkdwn(&f.impact));
        }
        if !f.why.is_empty() {
            let _ = write!(
                t,
                "\n*Why the tool does not fix this itself:* {}",
                mrkdwn(&f.why)
            );
        }
        if !f.todo.is_empty() {
            t.push_str("\n*What to do:*");
            for (i, s) in f.todo.iter().enumerate() {
                let _ = write!(t, "\n{}. {}", i + 1, mrkdwn(s));
            }
        }
        blocks.push(section(&t));
        if let Some(tab) = f.table.as_ref().filter(|t| !t.rows.is_empty()) {
            let mut s = slack_table(tab, 12);
            if tab.rows.len() > 12 {
                let _ = write!(s, "\n_And {} more._", tab.rows.len() - 12);
            }
            blocks.push(section(&s));
        }
    }
    if !m.log.is_empty() && m.event == Event::Failure {
        let tail = m.log_tail(15);
        blocks.push(json!({ "type": "divider" }));
        blocks.push(section(&format!(
            "*Last {} lines of the log*\n```{}```",
            tail.len(),
            truncate(&mrkdwn(&tail.join("\n")), 2700)
        )));
    }
    let mut ctx = mrkdwn(&m.footer());
    if let Some(p) = &m.log_path {
        let _ = write!(ctx, " Full log: `{}` on {}.", mrkdwn(p), mrkdwn(&m.host));
    }
    if let Some(u) = &m.gui_url {
        let _ = write!(
            ctx,
            " <{}|Open the admin GUI>",
            u.replace(['<', '>', '|'], "")
        );
    }
    blocks.push(json!({ "type": "context", "elements": [ { "type": "mrkdwn", "text": truncate(&ctx, 2900) } ] }));
    blocks.truncate(50);
    json!({
        "text": format!("{}: {}", m.event.label(), m.headline),
        "blocks": blocks,
        "unfurl_links": false,
    })
}

// ------------------------------------------------------------------ webhook

pub const WEBHOOK_SCHEMA: &str = "afas-entra-sync/notification/v1";

/// The whole message as JSON: every finding with every row, the full log and the report.
pub fn webhook(m: &Message) -> Value {
    json!({
        "schema": WEBHOOK_SCHEMA,
        "id": m.id,
        "event": m.event,
        "created_utc": m.created_utc,
        "source": m.source,
        "population": m.population,
        "host": m.host,
        "headline": m.headline,
        "summary": m.lead,
        "facts": m.facts.iter().map(|(k, v)| json!({ "label": k, "value": v })).collect::<Vec<_>>(),
        "findings": m.findings,
        "log": m.log,
        "log_path": m.log_path,
        "report": m.report,
        "gui_url": m.gui_url,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notify::findings::examples;

    fn msg() -> Message {
        Message {
            id: "x".into(),
            event: Event::Attention,
            source: "Sync".into(),
            population: None,
            headline: "2 points need attention after the sync".into(),
            lead: "The sync itself went well.".into(),
            facts: vec![("Run".into(), "Sync (scheduled)".into())],
            findings: examples(),
            log: (0..60).map(|i| format!("line {i} <b>")).collect(),
            log_path: Some("/var/lib/afas-entra-sync/last-run.log".into()),
            report: None,
            gui_url: Some("https://sync.example.com".into()),
            host: "sync01".into(),
            channel: "IT".into(),
            repeat_hours: 24,
            created_utc: "2026-11-03T10:07:00Z".into(),
        }
    }

    #[test]
    fn email_is_escaped_and_tells_the_whole_story() {
        let (subject, html) = email(&msg());
        assert!(subject.starts_with("[AFAS → Entra] Needs attention: 2 points"));
        for part in [
            "What happened",
            "What this means",
            "Why the tool does not fix this itself",
            "What to do",
            "For HR",
            "NEW",
            "Open the admin GUI",
            "line 59 &lt;b&gt;",
            "all 60 lines are attached as run.log",
            "at most once every 24 hours",
        ] {
            assert!(html.contains(part), "missing {part}");
        }
        assert!(!html.contains("line 10 ") && !html.contains("<b>"));
    }

    #[test]
    fn teams_card_fits_and_hides_the_log_behind_a_toggle() {
        let mut m = msg();
        m.findings = (0..30).flat_map(|_| examples()).collect();
        let v = teams(&m);
        assert!(v.to_string().len() <= TEAMS_MAX_BYTES);
        let card = &v["attachments"][0]["content"];
        assert_eq!(card["type"], "AdaptiveCard");
        assert_eq!(card["version"], "1.5");
        let small = teams(&msg());
        let s = small.to_string();
        assert!(s.contains("Action.ToggleVisibility") && s.contains("\"isVisible\":false"));
        assert!(s.contains("\"type\":\"Table\""));
    }

    #[test]
    fn slack_respects_its_limits() {
        let mut m = msg();
        m.findings = (0..40).flat_map(|_| examples()).collect();
        let v = slack(&m);
        let blocks = v["blocks"].as_array().unwrap();
        assert!(blocks.len() <= 50);
        assert!(blocks.iter().all(|b| {
            b["text"]["text"]
                .as_str()
                .is_none_or(|t| t.chars().count() <= 3000)
        }));
        assert!(v["text"].as_str().unwrap().starts_with("Needs attention"));
        let one = slack(&msg()).to_string();
        assert!(one.contains("&lt;b&gt;") || !one.contains("<b>"));
        assert!(one.contains("<https://sync.example.com|Open the admin GUI>"));
    }

    #[test]
    fn webhook_has_everything() {
        let v = webhook(&msg());
        assert_eq!(v["schema"], WEBHOOK_SCHEMA);
        assert_eq!(v["event"], "attention");
        assert_eq!(v["log"].as_array().unwrap().len(), 60);
        assert_eq!(v["findings"][0]["kind"], "manager_gone");
    }
}
