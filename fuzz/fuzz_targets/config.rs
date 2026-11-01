// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The afas-entra-sync Authors
//! Any configuration text, and any overrides layered on the example configuration:
//! accepted or refused with an error, never a panic.
#![no_main]

use afas_entra_sync::config::Config;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let _ = Config::parse(text);
    if let (Ok(base), Ok(over)) = (
        include_str!("../../afas-entra-sync.example.toml").parse::<toml::Table>(),
        text.parse::<toml::Table>(),
    ) {
        if let Ok(l) = Config::combine(base, over) {
            let _ = l.config.validate();
        }
    }
});
