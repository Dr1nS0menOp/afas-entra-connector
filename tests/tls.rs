// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The afas-entra-sync Authors
//! TLS policy tests against a real local TLS server (rustls), including a CONNECT proxy.

use afas_entra_sync::config::{PostQuantum, TlsConfig, TlsVersion};
use afas_entra_sync::tls::{client_config_with, probe, provider};
use rustls::crypto::aws_lc_rs::kx_group;
use rustls::crypto::{SupportedKxGroup, aws_lc_rs};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{RootCertStore, ServerConfig, ServerConnection, SupportedProtocolVersion};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

struct TestServer {
    port: u16,
    root: CertificateDer<'static>,
}

fn cert() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let der = ck.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der()));
    (der, key)
}

/// One-connection TLS server with the given groups and versions.
fn server(
    groups: Vec<&'static dyn SupportedKxGroup>,
    versions: &'static [&'static SupportedProtocolVersion],
) -> TestServer {
    let (der, key) = cert();
    let mut p = aws_lc_rs::default_provider();
    p.kx_groups = groups;
    let cfg = ServerConfig::builder_with_provider(Arc::new(p))
        .with_protocol_versions(versions)
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![der.clone()], key)
        .unwrap();
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let cfg = Arc::new(cfg);
    std::thread::spawn(move || {
        if let Ok((mut s, _)) = l.accept() {
            s.set_read_timeout(Some(Duration::from_secs(5))).ok();
            let mut conn = ServerConnection::new(cfg).unwrap();
            while conn.is_handshaking() {
                if conn.complete_io(&mut s).is_err() {
                    return;
                }
            }
            let _ = conn.complete_io(&mut s);
        }
    });
    TestServer { port, root: der }
}

fn client(t: TlsConfig, root: &CertificateDer<'static>) -> Arc<rustls::ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.add(root.clone()).unwrap();
    let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::new(aws_lc_rs::default_provider()),
    )
    .build()
    .unwrap();
    Arc::new(client_config_with(&t, verifier).unwrap())
}

fn tls(min: TlsVersion, pq: PostQuantum) -> TlsConfig {
    TlsConfig {
        min_version: min,
        post_quantum: pq,
    }
}

static V13: [&SupportedProtocolVersion; 1] = [&rustls::version::TLS13];
static V12: [&SupportedProtocolVersion; 1] = [&rustls::version::TLS12];

fn run(s: &TestServer, t: TlsConfig) -> afas_entra_sync::tls::Probe {
    probe(
        "test",
        "localhost",
        s.port,
        None,
        client(t, &s.root),
        Duration::from_secs(5),
    )
}

#[test]
fn default_policy_negotiates_post_quantum_tls13() {
    let s = server(vec![kx_group::X25519MLKEM768, kx_group::X25519], &V13);
    let p = run(&s, TlsConfig::default());
    assert!(p.ok, "{p:?}");
    assert_eq!(p.protocol.as_deref(), Some("TLSv1_3"));
    assert_eq!(p.key_exchange.as_deref(), Some("X25519MLKEM768"));
    assert!(p.post_quantum);
}

#[test]
fn prefer_falls_back_to_classical_when_server_has_no_ml_kem() {
    let s = server(vec![kx_group::X25519], &V13);
    let p = run(&s, TlsConfig::default());
    assert!(p.ok, "{p:?}");
    assert_eq!(p.key_exchange.as_deref(), Some("X25519"));
    assert!(!p.post_quantum);
}

#[test]
fn require_refuses_a_server_without_ml_kem() {
    let s = server(vec![kx_group::X25519, kx_group::SECP384R1], &V13);
    let p = run(&s, tls(TlsVersion::V13, PostQuantum::Require));
    assert!(!p.ok, "{p:?}");
    let s = server(vec![kx_group::X25519MLKEM768], &V13);
    let p = run(&s, tls(TlsVersion::V13, PostQuantum::Require));
    assert!(p.ok && p.post_quantum, "{p:?}");
}

#[test]
fn tls12_only_server_is_refused_by_default_and_allowed_with_min_12() {
    let s = server(vec![kx_group::X25519], &V12);
    let p = run(&s, TlsConfig::default());
    assert!(!p.ok, "TLS 1.2 must be refused with min_version 1.3: {p:?}");
    let s = server(vec![kx_group::X25519], &V12);
    let p = run(&s, tls(TlsVersion::V12, PostQuantum::Prefer));
    assert!(p.ok, "{p:?}");
    assert_eq!(p.protocol.as_deref(), Some("TLSv1_2"));
}

#[test]
fn untrusted_certificate_is_refused() {
    let s = server(vec![kx_group::X25519], &V13);
    let (other, _) = cert();
    let p = probe(
        "test",
        "localhost",
        s.port,
        None,
        client(TlsConfig::default(), &other),
        Duration::from_secs(5),
    );
    assert!(!p.ok);
    assert!(p.error.unwrap().contains("handshake"));
}

#[test]
fn wrong_host_name_is_refused() {
    let s = server(vec![kx_group::X25519], &V13);
    // Certificate is for "localhost"; connect by IP name instead.
    let p = probe(
        "test",
        "127.0.0.1",
        s.port,
        None,
        client(TlsConfig::default(), &s.root),
        Duration::from_secs(5),
    );
    assert!(!p.ok, "{p:?}");
}

/// Minimal CONNECT proxy for one connection.
fn proxy(answer_ok: bool) -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let (c, _) = l.accept().unwrap();
        let mut r = BufReader::new(c.try_clone().unwrap());
        let mut first = String::new();
        r.read_line(&mut first).unwrap();
        loop {
            let mut l = String::new();
            r.read_line(&mut l).unwrap();
            if l == "\r\n" {
                break;
            }
        }
        let mut c = c;
        if !answer_ok {
            c.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n").unwrap();
            return;
        }
        let target = first.split_whitespace().nth(1).unwrap().to_string();
        let target = target.replace("localhost", "127.0.0.1");
        let up = TcpStream::connect(target).unwrap();
        c.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .unwrap();
        let (mut c2, mut up2) = (c.try_clone().unwrap(), up.try_clone().unwrap());
        let (mut c, mut up) = (c, up);
        std::thread::spawn(move || {
            let _ = std::io::copy(&mut c2, &mut up2);
        });
        let mut buf = [0u8; 8192];
        loop {
            match up.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if c.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            }
        }
    });
    port
}

#[test]
fn probe_through_connect_proxy() {
    let s = server(vec![kx_group::X25519MLKEM768], &V13);
    let px = format!("127.0.0.1:{}", proxy(true));
    let p = probe(
        "test",
        "localhost",
        s.port,
        Some(&px),
        client(TlsConfig::default(), &s.root),
        Duration::from_secs(5),
    );
    assert!(p.ok && p.post_quantum, "{p:?}");
    assert_eq!(p.via_proxy.as_deref(), Some(px.as_str()));
    let px = format!("127.0.0.1:{}", proxy(false));
    let p = probe(
        "test",
        "localhost",
        s.port,
        Some(&px),
        client(TlsConfig::default(), &s.root),
        Duration::from_secs(5),
    );
    assert!(!p.ok);
    assert!(p.error.unwrap().contains("403"));
}

/// The real HTTP client (reqwest) must use the same policy: a TLS 1.2-only server fails on
/// the protocol version, before the certificate is even looked at.
#[test]
fn http_client_enforces_policy() {
    use std::error::Error;
    let chain = |e: &reqwest::Error| {
        let mut s = e.to_string();
        let mut cur: Option<&dyn Error> = e.source();
        while let Some(c) = cur {
            s.push_str(" | ");
            s.push_str(&c.to_string());
            cur = c.source();
        }
        s
    };
    let s = server(vec![kx_group::X25519], &V12);
    let c = afas_entra_sync::http::build_client(5, false, &TlsConfig::default()).unwrap();
    let e = c
        .get(format!("https://localhost:{}/", s.port))
        .send()
        .unwrap_err();
    let msg = chain(&e);
    assert!(
        msg.contains("PeerIncompatible")
            || msg.contains("protocol version")
            || msg.contains("ProtocolVersion"),
        "{msg}"
    );
    // TLS 1.3 server: handshake gets to certificate checking (self-signed: refused).
    let s = server(vec![kx_group::X25519MLKEM768], &V13);
    let e = c
        .get(format!("https://localhost:{}/", s.port))
        .send()
        .unwrap_err();
    let msg = chain(&e);
    assert!(msg.to_lowercase().contains("certificate"), "{msg}");
}

#[test]
fn provider_group_order() {
    let names = |t: TlsConfig| -> Vec<String> {
        provider(&t)
            .kx_groups
            .iter()
            .map(|g| format!("{:?}", g.name()))
            .collect()
    };
    assert_eq!(
        names(TlsConfig::default()),
        ["X25519MLKEM768", "X25519", "secp384r1", "secp256r1"]
    );
    let req = names(tls(TlsVersion::V13, PostQuantum::Require));
    assert!(req.iter().all(|n| n.contains("MLKEM")), "{req:?}");
}

#[test]
fn tls_config_parsing_and_lock() {
    use afas_entra_sync::config::is_locked;
    assert!(is_locked("tls.min_version") && is_locked("tls.post_quantum"));
    let parse = |s: &str| toml::from_str::<TlsConfig>(s);
    assert_eq!(parse("").unwrap(), TlsConfig::default());
    assert_eq!(TlsConfig::default().min_version, TlsVersion::V13);
    assert_eq!(TlsConfig::default().post_quantum, PostQuantum::Prefer);
    assert!(parse("min_version = \"1.1\"").is_err());
    assert!(parse("min_version = \"1.0\"").is_err());
    assert!(parse("post_quantum = \"off\"").is_err());
    assert!(parse("ciphers = \"all\"").is_err());
    assert_eq!(
        parse("min_version = \"1.2\"\npost_quantum = \"require\"").unwrap(),
        tls(TlsVersion::V12, PostQuantum::Require)
    );
}

#[test]
fn every_policy_combination_builds() {
    for min in [TlsVersion::V12, TlsVersion::V13] {
        for pq in [PostQuantum::Prefer, PostQuantum::Require] {
            afas_entra_sync::tls::client_config(&tls(min, pq))
                .unwrap_or_else(|e| panic!("{min:?} {pq:?}: {e}"));
        }
    }
    // require + 1.2 still negotiates 1.3 with a PQ server (ML-KEM exists only in 1.3).
    let s = server(vec![kx_group::X25519MLKEM768], &V13);
    let p = run(&s, tls(TlsVersion::V12, PostQuantum::Require));
    assert!(p.ok && p.post_quantum, "{p:?}");
    assert_eq!(p.protocol.as_deref(), Some("TLSv1_3"));
}
