// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The afas-entra-sync Authors
//! TLS policy for every outgoing connection, and the `check-tls` probe.
//!
//! - TLS 1.3 only by default (`[tls] min_version = "1.3"`).
//! - Post-quantum hybrid key exchange X25519MLKEM768 is offered first. With
//!   `post_quantum = "require"` only hybrid post-quantum groups are offered, so a
//!   server without ML-KEM support is refused.
//! - Certificates are checked against the operating system trust store.
//! - Crypto comes from aws-lc-rs.

use crate::config::{PostQuantum, TlsConfig, TlsVersion};
use rustls::client::danger::ServerCertVerifier;
use rustls::crypto::{CryptoProvider, aws_lc_rs};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, SupportedProtocolVersion};
use rustls_platform_verifier::BuilderVerifierExt;
use serde::Serialize;
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

/// Hybrid post-quantum groups, strongest classical partner last.
const PQ_NAMES: [&str; 2] = ["X25519MLKEM768", "secp256r1MLKEM768"];

pub fn provider(t: &TlsConfig) -> CryptoProvider {
    use aws_lc_rs::kx_group::{SECP256R1, SECP256R1MLKEM768, SECP384R1, X25519, X25519MLKEM768};
    let mut p = aws_lc_rs::default_provider();
    p.kx_groups = match t.post_quantum {
        PostQuantum::Prefer => vec![X25519MLKEM768, X25519, SECP384R1, SECP256R1],
        PostQuantum::Require => vec![X25519MLKEM768, SECP256R1MLKEM768],
    };
    p
}

static ONLY_13: [&SupportedProtocolVersion; 1] = [&rustls::version::TLS13];
static FROM_12: [&SupportedProtocolVersion; 2] = [&rustls::version::TLS13, &rustls::version::TLS12];

pub fn versions(t: &TlsConfig) -> &'static [&'static SupportedProtocolVersion] {
    match t.min_version {
        TlsVersion::V13 => &ONLY_13,
        TlsVersion::V12 => &FROM_12,
    }
}

/// Client configuration with the system trust store.
pub fn client_config(t: &TlsConfig) -> Result<ClientConfig, String> {
    ClientConfig::builder_with_provider(Arc::new(provider(t)))
        .with_protocol_versions(versions(t))
        .map_err(|e| format!("TLS configuration: {e}"))?
        .with_platform_verifier()
        .map_err(|e| format!("cannot load the system trust store: {e}"))
        .map(|b| b.with_no_client_auth())
}

/// Client configuration with an explicit verifier (tests, custom roots).
pub fn client_config_with(
    t: &TlsConfig,
    verifier: Arc<dyn ServerCertVerifier>,
) -> Result<ClientConfig, String> {
    Ok(ClientConfig::builder_with_provider(Arc::new(provider(t)))
        .with_protocol_versions(versions(t))
        .map_err(|e| format!("TLS configuration: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth())
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Probe {
    pub endpoint: String,
    pub host: String,
    pub port: u16,
    pub via_proxy: Option<String>,
    pub ok: bool,
    pub protocol: Option<String>,
    pub cipher_suite: Option<String>,
    pub key_exchange: Option<String>,
    pub post_quantum: bool,
    pub error: Option<String>,
}

/// Does a full TLS handshake with `host:port` (directly or through an HTTP CONNECT
/// proxy) and reports what was negotiated. Sends no application data.
pub fn probe(
    endpoint: &str,
    host: &str,
    port: u16,
    proxy: Option<&str>,
    cfg: Arc<ClientConfig>,
    timeout: Duration,
) -> Probe {
    let mut p = Probe {
        endpoint: endpoint.into(),
        host: host.into(),
        port,
        via_proxy: proxy.map(str::to_string),
        ok: false,
        protocol: None,
        cipher_suite: None,
        key_exchange: None,
        post_quantum: false,
        error: None,
    };
    match handshake(host, port, proxy, cfg, timeout) {
        Ok(conn) => {
            p.ok = true;
            p.protocol = conn.protocol_version().map(|v| format!("{v:?}"));
            p.cipher_suite = conn
                .negotiated_cipher_suite()
                .map(|c| format!("{:?}", c.suite()));
            p.key_exchange = conn
                .negotiated_key_exchange_group()
                .map(|g| format!("{:?}", g.name()));
            p.post_quantum = p
                .key_exchange
                .as_deref()
                .is_some_and(|k| PQ_NAMES.iter().any(|n| n.eq_ignore_ascii_case(k)));
        }
        Err(e) => p.error = Some(e),
    }
    p
}

fn connect(addr: &str, timeout: Duration) -> Result<TcpStream, String> {
    let addrs: Vec<SocketAddr> = addr
        .to_socket_addrs()
        .map_err(|e| format!("cannot resolve {addr}: {e}"))?
        .collect();
    let mut last = format!("no address for {addr}");
    for a in addrs {
        match TcpStream::connect_timeout(&a, timeout) {
            Ok(s) => {
                s.set_read_timeout(Some(timeout)).ok();
                s.set_write_timeout(Some(timeout)).ok();
                return Ok(s);
            }
            Err(e) => last = format!("cannot connect to {a}: {e}"),
        }
    }
    Err(last)
}

fn handshake(
    host: &str,
    port: u16,
    proxy: Option<&str>,
    cfg: Arc<ClientConfig>,
    timeout: Duration,
) -> Result<ClientConnection, String> {
    let mut sock = match proxy {
        None => connect(&format!("{host}:{port}"), timeout)?,
        Some(px) => {
            let mut s = connect(px, timeout)?;
            write!(
                s,
                "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n"
            )
            .map_err(|e| format!("proxy: {e}"))?;
            let mut r = BufReader::new(s.try_clone().map_err(|e| e.to_string())?);
            let mut status = String::new();
            r.read_line(&mut status)
                .map_err(|e| format!("proxy: {e}"))?;
            if status.split_whitespace().nth(1) != Some("200") {
                return Err(format!("proxy refused CONNECT: {}", status.trim()));
            }
            loop {
                let mut line = String::new();
                let n = r.read_line(&mut line).map_err(|e| format!("proxy: {e}"))?;
                if n == 0 || line == "\r\n" || line == "\n" {
                    break;
                }
            }
            if !r.buffer().is_empty() {
                return Err("proxy sent data before the TLS handshake".into());
            }
            s
        }
    };
    let name = ServerName::try_from(host.to_string()).map_err(|e| format!("host name: {e}"))?;
    let mut conn = ClientConnection::new(cfg, name).map_err(|e| e.to_string())?;
    while conn.is_handshaking() {
        conn.complete_io(&mut sock)
            .map_err(|e| format!("TLS handshake failed: {e}"))?;
    }
    conn.send_close_notify();
    let _ = conn.complete_io(&mut sock);
    Ok(conn)
}

/// Probes the three endpoints of a configuration (AFAS, Entra login, Graph).
pub fn check_endpoints(cfg: &crate::config::Config) -> Result<Vec<Probe>, String> {
    let tls_cfg = Arc::new(client_config(&cfg.tls)?);
    let mut probes = Vec::new();
    for (name, url) in [
        ("afas", cfg.afas.base_url.as_str()),
        ("entra_login", cfg.entra.authority.as_str()),
        ("graph", cfg.entra.graph_base.as_str()),
    ] {
        let u = reqwest::Url::parse(url).map_err(|_| format!("{name}: invalid URL {url}"))?;
        let (Some(host), Some(port)) = (u.host_str(), u.port_or_known_default()) else {
            return Err(format!("{name}: no host in {url}"));
        };
        if u.scheme() != "https" {
            return Err(format!("{name}: {url} is not https"));
        }
        let proxy = proxy_for(host);
        probes.push(probe(
            name,
            host,
            port,
            proxy.as_deref(),
            tls_cfg.clone(),
            Duration::from_secs(20),
        ));
    }
    Ok(probes)
}

/// Proxy from `HTTPS_PROXY`/`https_proxy` (http:// only), unless `NO_PROXY` matches.
pub fn proxy_for(host: &str) -> Option<String> {
    let raw = std::env::var("HTTPS_PROXY")
        .or_else(|_| std::env::var("https_proxy"))
        .ok()?;
    let no = std::env::var("NO_PROXY")
        .or_else(|_| std::env::var("no_proxy"))
        .unwrap_or_default();
    for n in no.split(',').map(str::trim).filter(|n| !n.is_empty()) {
        let n = n.trim_start_matches('*').trim_start_matches('.');
        if host == n || host.ends_with(&format!(".{n}")) {
            return None;
        }
    }
    let u = reqwest::Url::parse(&raw).ok()?;
    if u.scheme() != "http" {
        return None;
    }
    Some(format!("{}:{}", u.host_str()?, u.port_or_known_default()?))
}
