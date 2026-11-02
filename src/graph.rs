// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The afas-entra-sync Authors
//! Small Microsoft Graph client for the modules: retries on 429/5xx with
//! Retry-After, one token refresh on 401, paging that only follows links to the
//! same host, and capped response bodies.

use crate::entra::TokenProvider;
use crate::http::{MAX_LOG_BODY, backoff, read_capped, retry_after, snippet};
use reqwest::Method;
use reqwest::blocking::Client;
use serde_json::Value;
use std::cell::Cell;
use std::time::Duration;

const MAX_ATTEMPTS: u32 = 5;
const MAX_PAGES: usize = 1000;
const MAX_WAIT: Duration = Duration::from_secs(120);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphError {
    pub status: Option<u16>,
    pub code: String,
    pub message: String,
}

impl std::fmt::Display for GraphError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.status {
            Some(s) => write!(f, "HTTP {s} {}: {}", self.code, self.message),
            None => write!(f, "{}", self.message),
        }
    }
}

pub type GResult<T> = std::result::Result<T, GraphError>;

impl GraphError {
    /// The request may or may not have been carried out (network error or 5xx).
    pub fn outcome_unknown(&self) -> bool {
        self.status.is_none_or(|s| s >= 500)
    }
}

fn net(msg: String) -> GraphError {
    GraphError {
        status: None,
        code: String::new(),
        message: msg,
    }
}

pub struct Graph<'a> {
    base: reqwest::Url,
    client: &'a Client,
    tokens: TokenProvider<'a>,
    sleep: &'a dyn Fn(Duration),
    /// Number of HTTP calls made (for the report).
    pub calls: Cell<u32>,
}

impl<'a> Graph<'a> {
    pub fn new(
        graph_base: &str,
        client: &'a Client,
        tokens: TokenProvider<'a>,
        sleep: &'a dyn Fn(Duration),
    ) -> Result<Self, String> {
        let base = reqwest::Url::parse(&format!("{}/", graph_base.trim_end_matches('/')))
            .map_err(|e| format!("graph_base: {e}"))?;
        Ok(Graph {
            base,
            client,
            tokens,
            sleep,
            calls: Cell::new(0),
        })
    }

    /// A path relative to `graph_base` (e.g. `users?$top=999`), or a full URL on the same host.
    fn url(&self, path_or_url: &str) -> GResult<reqwest::Url> {
        let u = if path_or_url.starts_with("https://") || path_or_url.starts_with("http://") {
            reqwest::Url::parse(path_or_url).map_err(|e| net(format!("invalid URL: {e}")))?
        } else {
            self.base
                .join(path_or_url.trim_start_matches('/'))
                .map_err(|e| net(format!("invalid path: {e}")))?
        };
        if u.origin() != self.base.origin() {
            return Err(net(
                "refused: URL points to a different host than graph_base".into(),
            ));
        }
        Ok(u)
    }

    /// One request with retries. Returns the status and the JSON body (Null if empty).
    ///
    /// A POST is not idempotent (a second Temporary Access Pass, a second mail), so after a
    /// network error or a 5xx, where Graph may already have done it, a POST is not repeated:
    /// the caller decides. 429 and 401 are always safe to repeat (nothing was done).
    pub fn call(&self, method: Method, path: &str, body: Option<&Value>) -> GResult<(u16, Value)> {
        let url = self.url(path)?;
        let repeatable = method != Method::POST;
        let mut refreshed = false;
        let mut attempt = 0;
        loop {
            attempt += 1;
            let token = self
                .tokens
                .get(false)
                .map_err(|e| net(format!("token: {e}")))?;
            let mut req = self
                .client
                .request(method.clone(), url.clone())
                .bearer_auth(&token);
            if let Some(b) = body {
                req = req.json(b);
            }
            self.calls.set(self.calls.get() + 1);
            let wait = match req.send() {
                Err(e) => {
                    if attempt >= MAX_ATTEMPTS || !repeatable {
                        return Err(net(format!(
                            "network error: {}",
                            crate::http::error_chain(&e)
                        )));
                    }
                    backoff(attempt, 1000, 30_000)
                }
                Ok(r) => {
                    let status = r.status();
                    let headers = r.headers().clone();
                    let text = read_capped(r, MAX_LOG_BODY).unwrap_or_default();
                    if status.is_success() {
                        let v = if text.trim().is_empty() {
                            Value::Null
                        } else {
                            serde_json::from_str(&text)
                                .map_err(|e| net(format!("response is not JSON: {e}")))?
                        };
                        return Ok((status.as_u16(), v));
                    }
                    let err = parse_error(status.as_u16(), &text);
                    if status.as_u16() == 401 && !refreshed {
                        refreshed = true;
                        self.tokens
                            .get(true)
                            .map_err(|e| net(format!("token: {e}")))?;
                        Duration::ZERO
                    } else if (status.as_u16() == 429 || (status.is_server_error() && repeatable))
                        && attempt < MAX_ATTEMPTS
                    {
                        retry_after(&headers, chrono::Utc::now())
                            .unwrap_or_else(|| backoff(attempt, 1000, 30_000))
                            .min(MAX_WAIT)
                    } else {
                        return Err(err);
                    }
                }
            };
            if !wait.is_zero() {
                (self.sleep)(wait);
            }
        }
    }

    pub fn get(&self, path: &str) -> GResult<Value> {
        self.call(Method::GET, path, None).map(|(_, v)| v)
    }

    /// All items of a collection, following `@odata.nextLink` on the same host.
    pub fn get_all(&self, path: &str) -> GResult<Vec<Value>> {
        let mut out = Vec::new();
        let mut next = path.to_string();
        for _ in 0..MAX_PAGES {
            let v = self.get(&next)?;
            let items = v
                .get("value")
                .and_then(Value::as_array)
                .ok_or_else(|| net("response has no 'value' list".into()))?;
            out.extend(items.iter().cloned());
            match v.get("@odata.nextLink").and_then(Value::as_str) {
                None => return Ok(out),
                Some(n) => next = n.to_string(),
            }
        }
        Err(net(format!("more than {MAX_PAGES} pages; aborted")))
    }
}

fn parse_error(status: u16, body: &str) -> GraphError {
    let v: Value = serde_json::from_str(body).unwrap_or(Value::Null);
    GraphError {
        status: Some(status),
        code: v["error"]["code"].as_str().unwrap_or("").to_string(),
        message: v["error"]["message"]
            .as_str()
            .map_or_else(|| snippet(body, 300), |m| snippet(m, 300)),
    }
}

/// An Entra user as the modules need it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntraUser {
    pub id: String,
    pub upn: String,
    pub employee_id: Option<String>,
    pub mail: Option<String>,
    pub enabled: bool,
}

impl EntraUser {
    pub fn from_json(v: &Value) -> Option<Self> {
        Some(EntraUser {
            id: v["id"].as_str()?.to_string(),
            upn: v["userPrincipalName"].as_str().unwrap_or("").to_string(),
            employee_id: v["employeeId"]
                .as_str()
                .filter(|s| !s.is_empty())
                .map(str::to_string),
            mail: v["mail"]
                .as_str()
                .filter(|s| !s.is_empty())
                .map(str::to_string),
            enabled: v["accountEnabled"].as_bool().unwrap_or(false),
        })
    }
}

pub const USER_SELECT: &str = "id,userPrincipalName,employeeId,mail,accountEnabled";

pub fn list_users(g: &Graph<'_>) -> GResult<Vec<EntraUser>> {
    Ok(g.get_all(&format!("users?$select={USER_SELECT}&$top=999"))?
        .iter()
        .filter_map(EntraUser::from_json)
        .collect())
}

/// Path segment for an id that came from Graph or config: only GUID characters pass.
pub fn seg(id: &str) -> GResult<&str> {
    if !id.is_empty() && id.len() <= 64 && id.chars().all(|c| c.is_ascii_hexdigit() || c == '-') {
        Ok(id)
    } else {
        Err(net(format!(
            "refused unexpected object id '{}'",
            snippet(id, 40)
        )))
    }
}
