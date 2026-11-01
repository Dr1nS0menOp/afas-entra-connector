// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The afas-entra-sync Authors
//! Small parsers fed with outside data: AFAS dates, UPNs, the AFAS token, Retry-After,
//! form bodies, HTML escaping, Graph user objects.
#![no_main]

use afas_entra_sync::{afas, graph, http, model, web};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);
    let _ = model::parse_afas_date(&s);
    let _ = model::validate_upn(&s, &["example.com".to_string()]);
    let _ = afas::auth_header(&s);
    let _ = web::parse_form(data);
    let escaped = web::esc(&s);
    assert!(!escaped.contains(['<', '>', '"']), "esc left markup");
    let _ = http::snippet(&s, 40);
    let mut h = reqwest::header::HeaderMap::new();
    if let Ok(v) = reqwest::header::HeaderValue::from_bytes(data) {
        h.insert(reqwest::header::RETRY_AFTER, v);
        let _ = http::retry_after(&h, chrono::Utc::now());
    }
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(data) {
        let _ = graph::EntraUser::from_json(&v);
    }
    let _ = graph::seg(&s);
});
