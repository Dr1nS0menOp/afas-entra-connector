// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The afas-entra-sync Authors
//! Shared HTTP helpers: client, backoff, Retry-After and text truncation.

use reqwest::blocking::Client;
use std::time::Duration;

/// HTTP client for AFAS, Entra login and Graph, with the TLS policy from `[tls]`.
pub fn build_client(
    timeout_secs: u64,
    use_system_proxy: bool,
    tls: &crate::config::TlsConfig,
) -> Result<Client, String> {
    let mut b = Client::builder()
        .tls_backend_preconfigured(crate::tls::client_config(tls)?)
        .timeout(Duration::from_secs(timeout_secs))
        .connect_timeout(Duration::from_secs(timeout_secs.min(30)))
        .user_agent(concat!("afas-entra-sync/", env!("CARGO_PKG_VERSION")))
        .redirect(reqwest::redirect::Policy::none());
    if !use_system_proxy {
        b = b.no_proxy();
    }
    b.build()
        .map_err(|e| format!("cannot create HTTP client: {e}"))
}

/// A reqwest error with its causes ("error sending request" alone does not say whether
/// DNS, the connection, the proxy or TLS failed). The URL, long and already known from
/// the context, is replaced by `<url>`.
pub fn error_chain(e: &reqwest::Error) -> String {
    let mut s = e.to_string();
    if let Some(u) = e.url() {
        s = s.replace(u.as_str(), "<url>");
    }
    let mut cur = std::error::Error::source(e);
    while let Some(c) = cur {
        let m = c.to_string();
        if !m.is_empty() && !s.contains(&m) {
            s.push_str(": ");
            s.push_str(&m);
        }
        cur = c.source();
    }
    s
}

/// Reads a response body, refusing anything larger than `max` bytes, so a broken or
/// hostile endpoint cannot exhaust memory.
pub fn read_capped<R: std::io::Read>(r: R, max: u64) -> Result<String, String> {
    use std::io::Read;
    let mut buf = Vec::new();
    r.take(max + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("reading response failed: {e}"))?;
    if buf.len() as u64 > max {
        return Err(format!("response larger than {max} bytes; refused"));
    }
    String::from_utf8(buf).map_err(|_| "response is not valid UTF-8".to_string())
}

/// Body limits per endpoint.
pub const MAX_AFAS_BODY: u64 = 128 * 1024 * 1024;
pub const MAX_SMALL_BODY: u64 = 1024 * 1024;
pub const MAX_LOG_BODY: u64 = 32 * 1024 * 1024;

/// Exponential backoff without jitter: base * 2^(attempt-1), capped at max.
pub fn backoff(attempt: u32, base_ms: u64, max_ms: u64) -> Duration {
    let shift = attempt.saturating_sub(1).min(30);
    let ms = base_ms.saturating_mul(1u64 << shift).min(max_ms);
    Duration::from_millis(ms)
}

/// Retry-After as seconds or as an HTTP date. `None` if absent or unreadable.
pub fn retry_after(
    headers: &reqwest::header::HeaderMap,
    now: chrono::DateTime<chrono::Utc>,
) -> Option<Duration> {
    let v = headers
        .get(reqwest::header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim();
    if let Ok(secs) = v.parse::<u64>() {
        return Some(Duration::from_secs(secs));
    }
    let when = chrono::DateTime::parse_from_rfc2822(v).ok()?;
    let delta = when.with_timezone(&chrono::Utc) - now;
    Some(delta.to_std().unwrap_or(Duration::ZERO))
}

/// Truncates text for error messages (on a char boundary, never inside UTF-8).
pub fn snippet(s: &str, max_chars: usize) -> String {
    let mut out: String = s.chars().take(max_chars).collect();
    if s.chars().count() > max_chars {
        out.push('…');
    }
    out.replace(['\r', '\n'], " ")
}
