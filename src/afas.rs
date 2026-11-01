// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The afas-entra-sync Authors
//! Fetches an AFAS Profit GetConnector through the REST service.

use crate::config::AfasConfig;
use crate::error::{AppError, Result};
use crate::http::{MAX_AFAS_BODY, backoff, read_capped, snippet};
use base64::Engine;
use reqwest::StatusCode;
use reqwest::blocking::Client;
use serde_json::{Map, Value};
use std::time::Duration;

/// Upper bound as a safety net against an endless paging loop.
const MAX_ROWS: usize = 1_000_000;

/// Builds the Authorization header: `AfasToken <base64 of the XML token>`.
/// Accepts the full XML token or only the data value.
pub fn auth_header(raw_token: &str) -> Result<String> {
    let t = raw_token.trim();
    if t.is_empty() {
        return Err(AppError::Config("AFAS token is empty".into()));
    }
    let xml = if t.starts_with("<token>") {
        if !t.ends_with("</token>") || !t.contains("<data>") {
            return Err(AppError::Config(
                "AFAS token is not valid <token>…</token> XML".into(),
            ));
        }
        t.to_string()
    } else {
        if !t.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Err(AppError::Config(
                "AFAS token (data part) contains invalid characters".into(),
            ));
        }
        format!("<token><version>1</version><data>{t}</data></token>")
    };
    Ok(format!(
        "AfasToken {}",
        base64::engine::general_purpose::STANDARD.encode(xml.as_bytes())
    ))
}

pub fn read_token(cfg: &AfasConfig) -> Result<String> {
    if let Some(var) = &cfg.token_env {
        return std::env::var(var).map_err(|_| {
            AppError::Config(format!(
                "environment variable {var} (AFAS token) is not set"
            ))
        });
    }
    if let Some(path) = &cfg.token_file {
        crate::state::check_private_file(path, "AFAS token file")?;
        return std::fs::read_to_string(path).map_err(|e| {
            AppError::Config(format!(
                "cannot read AFAS token from {}: {e}",
                path.display()
            ))
        });
    }
    Err(AppError::Config("no AFAS token configured".into()))
}

pub fn fetch_rows(
    cfg: &AfasConfig,
    auth: &str,
    client: &Client,
    sleep: &dyn Fn(Duration),
) -> Result<Vec<Map<String, Value>>> {
    let base = format!(
        "{}/connectors/{}",
        cfg.base_url.trim_end_matches('/'),
        cfg.connector
    );
    let base = reqwest::Url::parse(&base)
        .map_err(|e| AppError::Config(format!("invalid AFAS URL: {e}")))?;

    let order = cfg.order_by_field.as_str();
    let take = cfg.page_size as usize;
    let mut all: Vec<Map<String, Value>> = Vec::new();
    let mut prev_first: Option<Map<String, Value>> = None;
    loop {
        let mut url = base.clone();
        url.query_pairs_mut()
            .append_pair("skip", &all.len().to_string())
            .append_pair("take", &take.to_string())
            .append_pair("orderbyfieldids", order);
        let page = fetch_page(&url, auth, client, cfg, sleep)?;
        if page.len() > take {
            return Err(AppError::Source(format!(
                "AFAS returned {} rows while {take} were requested; paging is unreliable",
                page.len()
            )));
        }
        if let (Some(prev), Some(first)) = (&prev_first, page.first())
            && prev == first
        {
            return Err(AppError::Source(
                "AFAS returned the same page twice; skip is being ignored".into(),
            ));
        }
        let done = page.len() < take;
        prev_first = page.first().cloned();
        all.extend(page);
        if all.len() > MAX_ROWS {
            return Err(AppError::Source(format!(
                "more than {MAX_ROWS} rows; aborted"
            )));
        }
        if done {
            return Ok(all);
        }
    }
}

/// The first `take` rows only (one request), for checks that need to see the fields.
pub fn fetch_sample(
    cfg: &AfasConfig,
    auth: &str,
    client: &Client,
    sleep: &dyn Fn(Duration),
    take: usize,
) -> Result<Vec<Map<String, Value>>> {
    let base = format!(
        "{}/connectors/{}",
        cfg.base_url.trim_end_matches('/'),
        cfg.connector
    );
    let mut url = reqwest::Url::parse(&base)
        .map_err(|e| AppError::Config(format!("invalid AFAS URL: {e}")))?;
    url.query_pairs_mut()
        .append_pair("skip", "0")
        .append_pair("take", &take.to_string())
        .append_pair("orderbyfieldids", &cfg.order_by_field);
    fetch_page(&url, auth, client, cfg, sleep)
}

fn fetch_page(
    url: &reqwest::Url,
    auth: &str,
    client: &Client,
    cfg: &AfasConfig,
    sleep: &dyn Fn(Duration),
) -> Result<Vec<Map<String, Value>>> {
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        let resp = client
            .get(url.clone())
            .header("Authorization", auth)
            .header("Accept", "application/json")
            .send();
        let retry_reason = match resp {
            Err(e) => format!("network error: {}", without_url(&e)),
            Ok(r) => {
                let status = r.status();
                let body = read_capped(r, MAX_AFAS_BODY)
                    .map_err(|e| AppError::Source(format!("AFAS response: {e}")));
                if status.is_success() {
                    return parse_rows(&body?);
                }
                let body = body.unwrap_or_default();
                if status.is_server_error() || status == StatusCode::TOO_MANY_REQUESTS {
                    format!("HTTP {status}: {}", snippet(&body, 200))
                } else {
                    return Err(AppError::Source(format!(
                        "AFAS rejected the request (HTTP {status}): {}",
                        snippet(&body, 300)
                    )));
                }
            }
        };
        if attempt >= cfg.max_attempts {
            return Err(AppError::Source(format!(
                "AFAS unreachable after {attempt} attempts: {retry_reason}"
            )));
        }
        tracing::warn!(attempt, reason = %retry_reason, "AFAS request failed, retrying");
        sleep(backoff(attempt, 2000, 30_000));
    }
}

pub fn parse_rows(body: &str) -> Result<Vec<Map<String, Value>>> {
    let v: Value = serde_json::from_str(body)
        .map_err(|e| AppError::Source(format!("AFAS response is not JSON: {e}")))?;
    let Value::Object(mut obj) = v else {
        return Err(AppError::Source(
            "AFAS response is not a JSON object".into(),
        ));
    };
    let Some(Value::Array(rows)) = obj.remove("rows") else {
        return Err(AppError::Source(
            "AFAS response is missing the 'rows' list".into(),
        ));
    };
    rows.into_iter()
        .enumerate()
        .map(|(i, r)| match r {
            Value::Object(m) => Ok(m),
            _ => Err(AppError::Source(format!(
                "AFAS row {} is not an object",
                i + 1
            ))),
        })
        .collect()
}

/// reqwest errors contain the URL; not secret here, but long.
fn without_url(e: &reqwest::Error) -> String {
    let mut s = e.to_string();
    if let Some(u) = e.url() {
        s = s.replace(u.as_str(), "<url>");
    }
    s
}
