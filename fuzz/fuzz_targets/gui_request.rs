// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The afas-entra-sync Authors
//! The admin GUI request handler with arbitrary method, path, headers and body, both
//! without and with a valid session and CSRF token. Nothing may panic, and without a
//! session nothing but the login flow may answer 200.
#![no_main]

use afas_entra_sync::web::{App, Request, SESSION_COOKIE, WebOptions, handle};
use libfuzzer_sys::fuzz_target;
use std::sync::{Arc, OnceLock};

fn app() -> &'static App {
    static A: OnceLock<App> = OnceLock::new();
    A.get_or_init(|| {
        // Fuzz harness only: a throwaway state directory for this process.
        // nosemgrep (temp-dir): fuzz harness only
        let dir = std::env::temp_dir().join(format!("afas-fuzz-gui-{}", std::process::id()));
        let state = dir.join("state");
        std::fs::create_dir_all(&state).expect("state dir");
        let cfg = include_str!("../../afas-entra-sync.example.toml")
            .replace("/var/lib/afas-entra-sync", state.to_str().expect("utf-8 path"))
            .replace("[gui]\nenabled = false", "[gui]\nenabled = true")
            .replace("https://12345.rest.afas.online", "http://127.0.0.1:1");
        let path = dir.join("config.toml");
        std::fs::write(&path, cfg).expect("config");
        let mut a = App::new(WebOptions {
            config_path: path,
            listen: "127.0.0.1:8080".parse().expect("addr"),
            read_only: false,
            trusted_proxy: None,
        })
        .expect("app");
        a.sleep = Arc::new(|_| {});
        a.use_system_proxy = false;
        a.run_inline = true;
        a
    })
}

/// A session for the signed-in half of the inputs. Renewed when an input signed it out.
fn session() -> String {
    static S: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);
    let mut s = S.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if s.is_none() || app().session_count() == 0 {
        *s = Some(app().new_session().expect("session"));
    }
    s.clone().unwrap_or_default()
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let a = app();
    let signed_in = data[0] & 1 == 1;
    let method = match data[0] >> 1 & 3 {
        0 => "GET",
        1 => "POST",
        2 => "HEAD",
        _ => "PUT",
    };
    let rest = String::from_utf8_lossy(&data[1..]);
    let (path, body) = rest.split_once('\n').unwrap_or((&rest, ""));
    // Switching the GUI off would end every later run; the switch has its own tests.
    if path.starts_with("/gui/off") {
        return;
    }
    let mut headers = vec![("host".to_string(), "127.0.0.1:8080".to_string())];
    let mut form = body.to_string();
    if signed_in {
        let id = session();
        headers.push(("cookie".into(), format!("{SESSION_COOKIE}={id}")));
        form = format!("csrf={}&{body}", a.csrf);
    }
    let r = handle(
        a,
        &Request {
            method,
            path,
            remote: Some("127.0.0.1".parse().expect("ip")),
            headers: &headers,
            body: form.as_bytes(),
        },
    );
    if !signed_in {
        assert!(
            r.status != 200 || path.starts_with("/login"),
            "unauthenticated 200 for {method} {path}"
        );
    }
});
