// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The afas-entra-sync Authors
//! Entra ID: getting a token (certificate or secret), bulkUpload and provisioning logs.

use crate::config::{AuthMode, EntraConfig, UploadConfig};
use crate::error::{AppError, Result};
use crate::http::{MAX_LOG_BODY, MAX_SMALL_BODY, backoff, read_capped, retry_after, snippet};
use base64::Engine;
use reqwest::StatusCode;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha1::Digest;
use std::cell::RefCell;
use std::time::{Duration, Instant};

const GRAPH_SCOPE: &str = "https://graph.microsoft.com/.default";
const TOKEN_ATTEMPTS: u32 = 4;
/// Refresh the token if it expires within this time.
const TOKEN_MARGIN: Duration = Duration::from_secs(300);

pub enum Credential {
    Secret(String),
    Certificate {
        key_pem: Vec<u8>,
        x5t: String,
        x5t_s256: String,
    },
}

impl Credential {
    pub fn from_config(cfg: &EntraConfig) -> Result<Self> {
        match cfg.auth {
            AuthMode::ClientSecret => {
                let var = cfg.client_secret_env.as_deref().unwrap_or_default();
                let s = std::env::var(var).map_err(|_| {
                    AppError::Config(format!(
                        "environment variable {var} (client secret) is not set"
                    ))
                })?;
                if s.trim().is_empty() {
                    return Err(AppError::Config("client secret is empty".into()));
                }
                Ok(Credential::Secret(s.trim().to_string()))
            }
            AuthMode::Certificate => {
                let cert_path = cfg
                    .certificate_pem
                    .as_ref()
                    .ok_or_else(|| AppError::Config("certificate_pem is missing".into()))?;
                let key_path = cfg
                    .private_key_pem
                    .as_ref()
                    .ok_or_else(|| AppError::Config("private_key_pem is missing".into()))?;
                crate::state::check_private_file(key_path, "private key")?;
                let cert = std::fs::read(cert_path).map_err(|e| {
                    AppError::Config(format!("cannot read {}: {e}", cert_path.display()))
                })?;
                let key_pem = std::fs::read(key_path).map_err(|e| {
                    AppError::Config(format!("cannot read {}: {e}", key_path.display()))
                })?;
                Self::certificate(&cert, key_pem)
            }
        }
    }

    pub fn certificate(cert_pem: &[u8], key_pem: Vec<u8>) -> Result<Self> {
        let blocks = pem::parse_many(cert_pem)
            .map_err(|e| AppError::Config(format!("certificate PEM invalid: {e}")))?;
        let certs: Vec<_> = blocks.iter().filter(|b| b.tag() == "CERTIFICATE").collect();
        let [cert] = certs.as_slice() else {
            return Err(AppError::Config(format!(
                "certificate_pem must contain exactly one CERTIFICATE (found: {})",
                certs.len()
            )));
        };
        // Load the key now so an error shows at startup, not only at the first call.
        jsonwebtoken::EncodingKey::from_rsa_pem(&key_pem)
            .map_err(|e| AppError::Config(format!("private key is not a valid RSA PEM: {e}")))?;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        Ok(Credential::Certificate {
            key_pem,
            x5t: b64.encode(sha1::Sha1::digest(cert.contents())),
            x5t_s256: b64.encode(sha2::Sha256::digest(cert.contents())),
        })
    }
}

#[derive(Serialize)]
struct AssertionClaims<'a> {
    aud: &'a str,
    iss: &'a str,
    sub: &'a str,
    jti: String,
    nbf: i64,
    iat: i64,
    exp: i64,
}

/// Signed client assertion (RFC 7523) as Entra ID expects it.
pub fn client_assertion(
    token_url: &str,
    client_id: &str,
    key_pem: &[u8],
    x5t: &str,
    x5t_s256: &str,
    now_unix: i64,
) -> Result<String> {
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.typ = Some("JWT".into());
    header.x5t = Some(x5t.to_string());
    header.x5t_s256 = Some(x5t_s256.to_string());
    let claims = AssertionClaims {
        aud: token_url,
        iss: client_id,
        sub: client_id,
        jti: uuid::Uuid::new_v4().to_string(),
        nbf: now_unix - 60,
        iat: now_unix,
        exp: now_unix + 600,
    };
    let key = jsonwebtoken::EncodingKey::from_rsa_pem(key_pem)
        .map_err(|e| AppError::Auth(format!("private key: {e}")))?;
    jsonwebtoken::encode(&header, &claims, &key)
        .map_err(|e| AppError::Auth(format!("signing failed: {e}")))
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
}

pub struct TokenProvider<'a> {
    cfg: &'a EntraConfig,
    client: &'a Client,
    cred: Credential,
    sleep: &'a dyn Fn(Duration),
    cached: RefCell<Option<(String, Instant)>>,
}

impl<'a> TokenProvider<'a> {
    pub fn new(
        cfg: &'a EntraConfig,
        client: &'a Client,
        cred: Credential,
        sleep: &'a dyn Fn(Duration),
    ) -> Self {
        Self {
            cfg,
            client,
            cred,
            sleep,
            cached: RefCell::new(None),
        }
    }

    pub fn token_url(&self) -> String {
        format!(
            "{}/{}/oauth2/v2.0/token",
            self.cfg.authority.trim_end_matches('/'),
            self.cfg.tenant_id
        )
    }

    pub fn get(&self, force_refresh: bool) -> Result<String> {
        if !force_refresh
            && let Some((tok, until)) = self.cached.borrow().as_ref()
            && Instant::now() + TOKEN_MARGIN < *until
        {
            return Ok(tok.clone());
        }
        let (tok, ttl) = self.request()?;
        *self.cached.borrow_mut() = Some((tok.clone(), Instant::now() + ttl));
        Ok(tok)
    }

    fn request(&self) -> Result<(String, Duration)> {
        let url = self.token_url();
        let mut attempt = 0;
        loop {
            attempt += 1;
            let mut form: Vec<(&str, String)> = vec![
                ("client_id", self.cfg.client_id.clone()),
                ("scope", GRAPH_SCOPE.into()),
                ("grant_type", "client_credentials".into()),
            ];
            match &self.cred {
                Credential::Secret(s) => form.push(("client_secret", s.clone())),
                Credential::Certificate {
                    key_pem,
                    x5t,
                    x5t_s256,
                } => {
                    let now = chrono::Utc::now().timestamp();
                    form.push((
                        "client_assertion_type",
                        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".into(),
                    ));
                    form.push((
                        "client_assertion",
                        client_assertion(&url, &self.cfg.client_id, key_pem, x5t, x5t_s256, now)?,
                    ));
                }
            }
            let reason = match self.client.post(&url).form(&form).send() {
                Err(e) => format!("network error: {e}"),
                Ok(r) => {
                    let status = r.status();
                    let body = read_capped(r, MAX_SMALL_BODY).unwrap_or_default();
                    if status.is_success() {
                        let t: TokenResponse = serde_json::from_str(&body).map_err(|e| {
                            AppError::Auth(format!("unexpected token response: {e}"))
                        })?;
                        if t.access_token.is_empty() {
                            return Err(AppError::Auth("received an empty access token".into()));
                        }
                        return Ok((t.access_token, Duration::from_secs(t.expires_in)));
                    }
                    if status.is_server_error() || status == StatusCode::TOO_MANY_REQUESTS {
                        format!("HTTP {status}")
                    } else {
                        // AAD error messages contain no secrets, but do contain useful AADSTS codes.
                        return Err(AppError::Auth(format!(
                            "token refused (HTTP {status}): {}",
                            aad_error(&body)
                        )));
                    }
                }
            };
            if attempt >= TOKEN_ATTEMPTS {
                return Err(AppError::Auth(format!(
                    "no token after {attempt} attempts: {reason}"
                )));
            }
            (self.sleep)(backoff(attempt, 2000, 30_000));
        }
    }
}

fn aad_error(body: &str) -> String {
    serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|v| {
            v.get("error_description")
                .and_then(Value::as_str)
                .map(|s| snippet(s, 300))
        })
        .unwrap_or_else(|| snippet(body, 300))
}

#[derive(Debug, Default, Clone, Serialize, PartialEq, Eq)]
pub struct UploadOutcome {
    pub calls_accepted: usize,
    pub retries: usize,
}

pub fn bulk_upload_url(cfg: &EntraConfig) -> String {
    format!(
        "{}/servicePrincipals/{}/synchronization/jobs/{}/bulkUpload",
        cfg.graph_base.trim_end_matches('/'),
        cfg.service_principal_id,
        cfg.job_id
    )
}

pub fn upload_all(
    requests: &[Value],
    cfg: &EntraConfig,
    up: &UploadConfig,
    client: &Client,
    tokens: &TokenProvider<'_>,
    sleep: &dyn Fn(Duration),
) -> Result<UploadOutcome> {
    let url = bulk_upload_url(cfg);
    let mut out = UploadOutcome::default();
    for (i, req) in requests.iter().enumerate() {
        let body = serde_json::to_vec(req).map_err(|e| AppError::Internal(e.to_string()))?;
        let mut attempt = 0u32;
        let mut refreshed = false;
        loop {
            attempt += 1;
            let token = tokens.get(false)?;
            let resp = client
                .post(&url)
                .bearer_auth(&token)
                .header("Content-Type", "application/scim+json")
                .body(body.clone())
                .send();
            let fail_ctx = || {
                format!(
                    "call {}/{} failed; calls 1..{} were accepted, the rest were not. The next run sends everything again",
                    i + 1,
                    requests.len(),
                    out.calls_accepted
                )
            };
            let wait = match resp {
                Err(e) => {
                    tracing::warn!(call = i + 1, attempt, error = %e, "network error during upload");
                    backoff(attempt, up.backoff_base_ms, up.backoff_max_ms)
                }
                Ok(r) => {
                    let status = r.status();
                    let headers = r.headers().clone();
                    let text = read_capped(r, MAX_SMALL_BODY).unwrap_or_default();
                    if status.is_success() {
                        if status != StatusCode::ACCEPTED {
                            tracing::warn!(%status, "bulkUpload returned 2xx but not 202; treated as accepted");
                        }
                        out.calls_accepted += 1;
                        break;
                    } else if status == StatusCode::UNAUTHORIZED && !refreshed {
                        refreshed = true;
                        tokens.get(true)?;
                        Duration::ZERO
                    } else if status == StatusCode::TOO_MANY_REQUESTS {
                        retry_after(&headers, chrono::Utc::now())
                            .unwrap_or_else(|| {
                                backoff(attempt, up.backoff_base_ms, up.backoff_max_ms)
                            })
                            .min(Duration::from_secs(up.max_retry_after_secs))
                    } else if status == StatusCode::INTERNAL_SERVER_ERROR
                        && text.to_ascii_lowercase().contains("bucket")
                    {
                        tracing::warn!("provisioning queue full (bucket full); waiting");
                        Duration::from_secs(up.bucket_full_wait_secs)
                    } else if status.is_server_error() {
                        backoff(attempt, up.backoff_base_ms, up.backoff_max_ms)
                    } else {
                        return Err(AppError::Upload(format!(
                            "HTTP {status}: {} — {}",
                            snippet(&text, 500),
                            fail_ctx()
                        )));
                    }
                }
            };
            if attempt >= up.max_attempts {
                return Err(AppError::Upload(format!(
                    "after {attempt} attempts — {}",
                    fail_ctx()
                )));
            }
            out.retries += 1;
            if !wait.is_zero() {
                sleep(wait);
            }
        }
        if i + 1 < requests.len() && up.pace_ms > 0 {
            sleep(Duration::from_millis(up.pace_ms));
        }
    }
    Ok(out)
}

#[derive(Debug, Default, Serialize, PartialEq, Eq)]
pub struct LogSummary {
    pub total: usize,
    pub success: usize,
    pub failure: usize,
    pub skipped: usize,
    pub warning: usize,
    pub other: usize,
    pub failures: Vec<LogFailure>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct LogFailure {
    pub activity_utc: String,
    pub source_id: String,
    pub action: String,
    pub reason: String,
}

const MAX_LOG_PAGES: usize = 200;

/// Reads provisioning logs of this job since `since`. Follows `@odata.nextLink`
/// only to the same host as `graph_base` (the token must not go anywhere else).
pub fn read_logs(
    cfg: &EntraConfig,
    client: &Client,
    tokens: &TokenProvider<'_>,
    since: chrono::DateTime<chrono::Utc>,
) -> Result<LogSummary> {
    let base = cfg.graph_base.trim_end_matches('/');
    let filter = format!(
        "jobId eq '{}' and activityDateTime ge {}",
        cfg.job_id,
        since.format("%Y-%m-%dT%H:%M:%SZ")
    );
    let mut url = reqwest::Url::parse(&format!("{base}/auditLogs/provisioning"))
        .map_err(|e| AppError::Config(format!("graph_base: {e}")))?;
    url.query_pairs_mut()
        .append_pair("$filter", &filter)
        .append_pair("$top", "500");
    let origin = url.origin();

    let mut sum = LogSummary::default();
    for _ in 0..MAX_LOG_PAGES {
        let token = tokens.get(false)?;
        let r = client
            .get(url.clone())
            .bearer_auth(&token)
            .send()
            .map_err(|e| AppError::Upload(format!("provisioning logs: network error: {e}")))?;
        let status = r.status();
        let text = read_capped(r, MAX_LOG_BODY)
            .map_err(|e| AppError::Upload(format!("provisioning logs: {e}")))?;
        if !status.is_success() {
            return Err(AppError::Upload(format!(
                "provisioning logs: HTTP {status}: {}",
                snippet(&text, 300)
            )));
        }
        let v: Value = serde_json::from_str(&text)
            .map_err(|e| AppError::Upload(format!("provisioning logs: not JSON: {e}")))?;
        let items = v
            .get("value")
            .and_then(Value::as_array)
            .ok_or_else(|| AppError::Upload("provisioning logs: 'value' is missing".into()))?;
        for item in items {
            sum.total += 1;
            let s = |path: &[&str]| -> String {
                let mut cur = item;
                for p in path {
                    match cur.get(*p) {
                        Some(n) => cur = n,
                        None => return String::new(),
                    }
                }
                cur.as_str().unwrap_or_default().to_string()
            };
            match s(&["provisioningStatusInfo", "status"]).as_str() {
                "success" => sum.success += 1,
                "skipped" => sum.skipped += 1,
                "warning" => sum.warning += 1,
                "failure" => {
                    sum.failure += 1;
                    sum.failures.push(LogFailure {
                        activity_utc: s(&["activityDateTime"]),
                        source_id: s(&["sourceIdentity", "id"]),
                        action: s(&["provisioningAction"]),
                        reason: s(&["provisioningStatusInfo", "errorInformation", "reason"]),
                    });
                }
                _ => sum.other += 1,
            }
        }
        match v.get("@odata.nextLink").and_then(Value::as_str) {
            None => return Ok(sum),
            Some(next) => {
                let next = reqwest::Url::parse(next)
                    .map_err(|e| AppError::Upload(format!("invalid nextLink: {e}")))?;
                if next.origin() != origin {
                    return Err(AppError::Upload(
                        "nextLink points to a different host; refused".into(),
                    ));
                }
                url = next;
            }
        }
    }
    Err(AppError::Upload(format!(
        "more than {MAX_LOG_PAGES} pages of provisioning logs; aborted"
    )))
}
