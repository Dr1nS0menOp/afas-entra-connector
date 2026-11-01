// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The afas-entra-sync Authors
//! Whatever AFAS returns: the response body is parsed, every row is checked against the
//! field mapping and turned into an employee. Nothing may panic.
#![no_main]

use afas_entra_sync::config::Config;
use afas_entra_sync::{afas, model};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

fn fields() -> &'static afas_entra_sync::config::FieldMap {
    static C: OnceLock<Config> = OnceLock::new();
    &C.get_or_init(|| {
        Config::parse(include_str!("../../afas-entra-sync.example.toml")).expect("example config")
    })
    .afas
    .fields
}

fuzz_target!(|data: &[u8]| {
    let Ok(body) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(rows) = afas::parse_rows(body) {
        let _ = model::check_schema(&rows, fields());
        for row in &rows {
            let _ = model::parse_row(row, fields());
        }
    }
});
