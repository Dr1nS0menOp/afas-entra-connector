#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The afas-entra-sync Authors
"""OWASP ASVS 5.0.0 Level 2 self-assessment of afas-entra-sync.

The official requirement list is fetched from the OWASP ASVS repository at the
v5.0.0_release tag and verified by SHA-256 before use. For every Level 1 and Level 2
requirement this script records a status and the evidence, and writes
docs/security/asvs-5.0-L2.csv.

    python3 docs/security/asvs_assessment.py            # regenerate the CSV
    python3 docs/security/asvs_assessment.py --check    # CI: CSV up to date, evidence resolves
    python3 docs/security/asvs_assessment.py --source <file.csv>   # offline, same checksum

--check fails when the committed CSV differs from what this script produces, or when any
evidence or security document points to a file, test or code symbol that does not exist.

Status values:
  Met               the application meets it; evidence points to code, tests or docs
  Met (deployment)  met when deployed as documented; the condition is in the evidence
  N/A               the application has no such feature; the reason is in the evidence

The requirement texts are from the OWASP ASVS, (c) OWASP Foundation, licensed CC BY-SA 4.0
(https://github.com/OWASP/ASVS); they are reproduced unchanged in the CSV.
"""

import csv
import glob
import hashlib
import io
import os
import re
import sys
import urllib.request

ASVS_COMMIT = "5cf9b032440be53ce345ab3c130fda46ba1ce7a2"  # tag v5.0.0_release
ASVS_PATH = "5.0/docs_en/OWASP_Application_Security_Verification_Standard_5.0.0_en.csv"
ASVS_URL = f"https://raw.githubusercontent.com/OWASP/ASVS/{ASVS_COMMIT}/{ASVS_PATH}"
ASVS_SHA256 = "98c8fe911b9edb403af8ee05d3ce8201ecac2659e313b053890a62847cdcf680"
OUT = "docs/security/asvs-5.0-L2.csv"

M, D, NA = "Met", "Met (deployment)", "N/A"

# Whole sections that do not apply, with the reason.
NA_SECTIONS = {
    "V3.5": None,  # handled per requirement below
    "V4.3": "No GraphQL.",
    "V4.4": "No WebSockets.",
    "V5.1": "No file upload. The GUI only offers fixed downloads (payload.json, access-log.csv).",
    "V5.2": "No file upload.",
    "V6.2": "No passwords: local mode signs in with a one-time link, proxy mode with the identity provider.",
    "V6.5": "No one-time passwords or lookup secrets. (The first sign-in codes for new hires are created by Entra, see V6.4.1.)",
    "V6.6": "No out-of-band authentication.",
    "V9.1": "The application accepts no self-contained tokens. It only creates signed client assertions for Entra (see V11).",
    "V9.2": "The application accepts no self-contained tokens.",
    "V10.2": "No authorization code flow: client credentials only.",
    "V10.3": "Not a resource server.",
    "V10.4": "Not an authorization server.",
    "V10.5": "Not an OpenID Connect relying party: the GUI gets the user from the trusted proxy.",
    "V10.6": "Not an OpenID Provider.",
    "V10.7": "Not an authorization server.",
    "V17.1": "No WebRTC.",
    "V17.2": "No WebRTC.",
    "V17.3": "No WebRTC.",
}
NA_SECTIONS.pop("V3.5")

R = {
    # V1 Encoding and Sanitization
    "V1.1.1": (M, "Form bodies are URL-decoded once in web::parse_form, before use; nothing decodes again (tests/web.rs form_parsing; fuzz target small_parsers)."),
    "V1.1.2": (M, "All HTML is built server-side and every dynamic value goes through web::esc as the last step (fuzz target small_parsers asserts esc leaves no markup)."),
    "V1.2.1": (M, "HTML context: web::esc encodes & < > \" ' for elements and attributes. CSV: records::access_csv quotes fields and defuses formulas. JSON: serde_json. No CSS or comments built from data (tests/web.rs output_is_escaped)."),
    "V1.2.2": (M, "URLs built from data use web::url_encode (access log filter). Outbound URLs come only from the locked config; Graph object ids pass graph::seg (GUID characters only)."),
    "V1.2.3": (M, "The GUI has no JavaScript (CSP default-src 'none'). JSON is produced by serde_json."),
    "V1.2.4": (NA, "No database."),
    "V1.2.5": (M, "The installer starts programs with std::process::Command and separate arguments, never a shell (src/install.rs); semgrep found no command injection."),
    "V1.2.6": (NA, "No LDAP: AD is reached by the Microsoft provisioning agent, not by this program."),
    "V1.2.7": (NA, "No XPath."),
    "V1.2.8": (NA, "No LaTeX."),
    "V1.2.9": (NA, "No regular expressions are built from input."),
    "V1.3.1": (NA, "No HTML input."),
    "V1.3.2": (M, "No eval or dynamic code execution (Rust, #![forbid(unsafe_code)])."),
    "V1.3.3": (M, "Values for Graph paths pass graph::seg; mailbox addresses pass joiner::mailbox; settings pass type and range checks before they are written (web::parse_field, Config::validate)."),
    "V1.3.4": (NA, "No SVG input."),
    "V1.3.5": (NA, "No template or markup language input. Mail and reply templates are plain text with fixed placeholders; the automatic reply is HTML-escaped (leaver::reply_html)."),
    "V1.3.6": (M, "No request goes to a URL from user input: AFAS, login, Graph and webhook addresses are locked in the config file; Graph paging follows only links to the same host (graph::Graph::url, tests graph_client::paging_follows_same_host_only...)."),
    "V1.3.7": (NA, "No template engine."),
    "V1.3.8": (NA, "No JNDI."),
    "V1.3.9": (NA, "No memcache."),
    "V1.3.10": (M, "Rust format strings are compile-time constants; input is never a format string."),
    "V1.3.11": (M, "Mail is sent through the Graph sendMail JSON API, not SMTP; recipients are checked addresses (settings::is_email)."),
    "V1.4.1": (M, "Rust with #![forbid(unsafe_code)]; bounds-checked slices; fuzzed (fuzz/)."),
    "V1.4.2": (M, "Numbers from input are range-checked before use (settings ranges, at most 365 days, lengths, counts); date arithmetic uses checked operations (checked_add_days, checked_sub_days)."),
    "V1.4.3": (M, "Rust ownership: no manual memory management, no unsafe."),
    "V1.5.1": (NA, "No XML parser. The AFAS token is read as text."),
    "V1.5.2": (M, "Deserialisation only into fixed Rust types (serde), with deny_unknown_fields for config and state; no polymorphic types."),
    # V2 Validation and Business Logic
    "V2.1.1": (M, "Input rules are documented per field: README (design principle, active or not, extra attributes), docs/GUIDE.md step 1, docs/MODULES.md."),
    "V2.1.2": (M, "Combined checks documented: end date not before start date, duplicate employee numbers and UPNs, manager in upload (README, design principle table)."),
    "V2.1.3": (M, "Limits documented: safety thresholds (README), module maximums per run (docs/MODULES.md), Microsoft API limits (README)."),
    "V2.2.1": (M, "Positive validation: UPN rules and allowed domains, dates, lengths, GUIDs, ranges (model.rs, config.rs, settings.rs; tests/unit.rs, tests/props.rs)."),
    "V2.2.2": (M, "All validation is server-side; the GUI has no client-side code."),
    "V2.2.3": (M, "Cross-field checks in Config::validate (e.g. keep_leavers_days below leaver_lookback_days, conflict groups in role rules) and in model::parse_row (end date after start date)."),
    "V2.3.1": (M, "Applying needs a typed confirmation; mass disable needs a second, different confirmation (tests/web.rs apply_requires_exact_confirmation)."),
    "V2.3.2": (M, "Safety thresholds and per-module maximums stop the run before anything changes (tests/e2e.rs, tests/modules.rs ..._maximum...)."),
    "V2.3.3": (M, "Uploads are idempotent (full set every run); state and config are written atomically (state::write_atomic); a failed run leaves the previous state."),
    "V2.3.4": (M, "One run at a time: lock file (exit 11); the GUI refuses a second run while one is busy (tests/web.rs second_run_while_busy_is_refused)."),
    "V2.4.1": (M, "Runs are serialised; Graph and upload calls are paced and capped (max_calls_per_run, Retry-After); request bodies capped (MAX_BODY); login secrets are 256-bit and single-use, so guessing is infeasible."),
    # V3 Web Frontend Security
    "V3.2.1": (M, "Every response has a fixed Content-Type, X-Content-Type-Options: nosniff and a CSP without scripts; downloads are attachments (web::serve)."),
    "V3.2.2": (M, "No client-side rendering; server-side escaping (V1.2.1)."),
    "V3.3.1": (M, "Session cookie __Host-afas_gui_session with Secure (web::SESSION_COOKIE; tests/web.rs local_mode_requires_login_link...; verified in Chromium over http://127.0.0.1)."),
    "V3.3.2": (M, "SameSite=Strict."),
    "V3.3.3": (M, "__Host- prefix."),
    "V3.3.4": (M, "HttpOnly; the session id is only sent in the cookie."),
    "V3.4.1": (D, "Strict-Transport-Security: max-age=31536000; includeSubDomains on every response. Browsers apply it over HTTPS, i.e. behind the TLS proxy; local mode is loopback only."),
    "V3.4.2": (M, "No CORS headers are sent: cross-origin reads are refused by the browser; Cross-Origin-Resource-Policy: same-origin."),
    "V3.4.3": (M, "Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'. No scripts at all."),
    "V3.4.4": (M, "X-Content-Type-Options: nosniff on every response."),
    "V3.4.5": (M, "Referrer-Policy: no-referrer."),
    "V3.4.6": (M, "CSP frame-ancestors 'none' (and X-Frame-Options: DENY)."),
    "V3.5.1": (M, "Every state-changing request is a POST with a CSRF token, plus SameSite=Strict and a Host check (tests/web.rs csrf_read_only_size_and_methods)."),
    "V3.5.2": (NA, "The application does not rely on CORS preflight (see V3.5.1)."),
    "V3.5.3": (M, "Changes only via POST; GET is read-only (other methods answer 405, tests/web.rs only_get_and_post_are_answered)."),
    "V3.5.4": (D, "The GUI is its own origin (own port locally, own host name behind the proxy, as documented in docs/GUIDE.md)."),
    "V3.5.5": (NA, "No postMessage."),
    "V3.7.1": (M, "Plain HTML and CSS only."),
    "V3.7.2": (M, "Redirects only to fixed local paths (web::redirect)."),
    # V4 API and Web Service
    "V4.1.1": (M, "Content-Type with charset=utf-8 on every text response (HTML, plain text, CSV, JSON)."),
    "V4.1.2": (D, "The GUI does not redirect HTTP to HTTPS itself; behind the proxy, Traefik does it for browsers. No machine endpoint redirects."),
    "V4.1.3": (D, "The user header is accepted only from the configured trusted proxy address (web::handle); Traefik with Authentik forward-auth overwrites it (docs/GUIDE.md, Admin GUI)."),
    "V4.2.1": (D, "Local mode: loopback only. Proxy mode: Traefik terminates and normalises HTTP before the GUI."),
    # V5 File Handling (5.1, 5.2 N/A by section)
    "V5.3.1": (NA, "Nothing uploaded; nothing served from a public folder."),
    "V5.3.2": (M, "File paths come from the config (state.dir) and fixed names; no user-supplied file names."),
    "V5.4.1": (M, "Downloads set Content-Disposition with a fixed file name (payload.json, access-log.csv)."),
    "V5.4.2": (M, "Fixed ASCII file names."),
    "V5.4.3": (NA, "No files from untrusted sources are served."),
    # V6 Authentication (6.2, 6.5, 6.6 N/A by section)
    "V6.1.1": (M, "Documented in docs/security/README.md (Sign-in): 256-bit single-use login link valid for 15 minutes; proxy mode delegates to Authentik and its brute-force controls."),
    "V6.1.2": (NA, "No passwords."),
    "V6.1.3": (M, "Two pathways, documented together in docs/security/README.md and docs/GUIDE.md: local login link, or trusted proxy with Authentik. Only one is active per process (web::validate_listen)."),
    "V6.3.1": (M, "Login secrets cannot be brute-forced (256 bits, single use, 15 minutes); refused attempts are logged (tests/web.rs login_link_expires_and_wrong_tokens_are_logged)."),
    "V6.3.2": (M, "No default accounts."),
    "V6.3.3": (D, "Local mode requires an SSH session as the service user to read the login link: enforce MFA or keys on SSH. Proxy mode: enforce MFA in Authentik (docs/security/README.md)."),
    "V6.3.4": (M, "No other pathways; /health only answers 'ok'."),
    "V6.4.1": (M, "Login links: 256-bit CSPRNG, expire after 15 minutes and after one use (tests/web.rs). First sign-in codes for new hires: created by Entra, valid from the start date for a limited time, optionally single use (docs/MODULES.md)."),
    "V6.4.2": (M, "No password hints or secret questions."),
    "V6.4.3": (NA, "No passwords to reset."),
    "V6.4.4": (NA, "No MFA factors managed by the application."),
    "V6.8.1": (NA, "One identity source per process."),
    "V6.8.2": (NA, "The application receives no authentication assertions; the trusted proxy has verified them."),
    "V6.8.3": (NA, "No SAML."),
    "V6.8.4": (D, "Authentication strength is enforced at the identity provider (Authentik policy)."),
    # V7 Session Management
    "V7.1.1": (M, "Documented: 30 minutes inactivity, 8 hours absolute (docs/security/README.md, GUI page 'GUI')."),
    "V7.1.2": (M, "Documented: at most 20 concurrent sessions; the oldest ends first (web::MAX_SESSIONS; tests/web.rs sessions_are_capped...)."),
    "V7.1.3": (D, "Proxy mode: Authentik owns the session; documented in docs/security/README.md."),
    "V7.2.1": (M, "Sessions are checked server-side (web::App::touch_session)."),
    "V7.2.2": (M, "Random reference tokens per sign-in (web::App::new_session)."),
    "V7.2.3": (M, "256 bits from the OS CSPRNG (getrandom), compared in constant time (web::ct_eq)."),
    "V7.2.4": (M, "A new session id on every sign-in (tests/web.rs secrets_are_random...)."),
    "V7.3.1": (M, "Inactivity timeout 30 minutes (tests/web.rs sessions_end_after_inactivity...)."),
    "V7.3.2": (M, "Absolute lifetime 8 hours (same test)."),
    "V7.4.1": (M, "Sign-out removes the session server-side; the old cookie is refused afterwards (tests/web.rs sign_out_ends_the_session...)."),
    "V7.4.2": (D, "No local accounts. Proxy mode: disabling the user in Authentik ends access."),
    "V7.4.3": (NA, "No authentication factors managed by the application."),
    "V7.4.4": (M, "Sign-out button on every page in local mode."),
    "V7.4.5": (M, "'Sign out all sessions' on the GUI page; a restart also ends all sessions (sessions are in memory)."),
    "V7.5.1": (NA, "No account attributes."),
    "V7.5.2": (M, "The GUI page shows the number of active sessions and ends them all (single administrator role)."),
    "V7.6.1": (D, "Proxy mode: session lifetime set in Authentik."),
    "V7.6.2": (M, "A session is only created by opening the login link (explicit action)."),
    # V8 Authorization
    "V8.1.1": (M, "Documented in docs/security/README.md (Authorization): one role, administrator; read-only mode for the whole server; who may reach the GUI is decided by SSH access or the Authentik policy."),
    "V8.1.2": (M, "Field-level: locked keys (addresses, secrets, TLS policy, module identities) are read-only in the GUI (config::LOCKED_KEYS)."),
    "V8.2.1": (M, "Every page and action requires a session or the trusted proxy (web::handle); read-only mode refuses all changes."),
    "V8.2.2": (M, "Single role; no per-object data owners. Employee data is visible to administrators by design."),
    "V8.2.3": (M, "Locked keys cannot be changed through the GUI (tests/web.rs locked_fields_are_shown_readonly...)."),
    "V8.3.1": (M, "All checks are server-side."),
    "V8.4.1": (NA, "Not multi-tenant: one config per installation."),
    # V10 OAuth (most sections N/A)
    "V10.1.1": (M, "Access tokens go only to the Graph host they were issued for: other hosts are refused (graph::Graph::url) and redirects are not followed (http::build_client)."),
    "V10.1.2": (NA, "No browser-based flow."),
    "V10.4.10": (M, "The confidential client authenticates with a certificate (private_key_jwt), recommended over a secret (entra::Credential)."),
    "V10.4.11": (M, "Least-privilege application permissions per app registration, documented in SECURITY.md and docs/MODULES.md."),
    # V11 Cryptography
    "V11.1.1": (M, "docs/security/CRYPTO-INVENTORY.md (key management and lifecycle)."),
    "V11.1.2": (M, "docs/security/CRYPTO-INVENTORY.md (inventory of keys, algorithms and certificates)."),
    "V11.2.1": (M, "rustls with AWS-LC (aws-lc-rs) for TLS and HMAC; AWS-LC is the library behind AWS's FIPS 140-3 validated module (this build uses its standard, non-FIPS variant). rcgen for the installer's key, jsonwebtoken for the client assertion, sha1 and sha2 (RustCrypto) for the certificate thumbprints Entra expects. No custom cryptography."),
    "V11.2.2": (M, "TLS version and post-quantum mode are configuration ([tls]); algorithms come from the library provider and change with it; the inventory lists every place to change."),
    "V11.2.3": (M, "RSA 3072 (128-bit security), TLS 1.3 AEAD suites, HMAC-SHA-256, SHA-256 thumbprints, 256-bit random secrets."),
    "V11.3.1": (M, "No ECB, no PKCS#1 v1.5 encryption: encryption only inside TLS 1.3 (AEAD)."),
    "V11.3.2": (M, "TLS 1.3 suites only by default (AES-GCM, ChaCha20-Poly1305)."),
    "V11.3.3": (M, "AEAD in TLS; webhook messages carry HMAC-SHA-256."),
    "V11.4.1": (M, "SHA-256 only (signatures, HMAC, thumbprints). SHA-1 appears only as the x5t certificate header Entra requires, next to x5t#S256; it is an identifier, not a security function."),
    "V11.4.2": (NA, "No passwords stored."),
    "V11.4.3": (M, "SHA-256 for signatures (RS256) and HMAC."),
    "V11.4.4": (NA, "No keys derived from passwords."),
    "V11.5.1": (M, "Secrets from the OS CSPRNG, 256 bits (getrandom); UUID v4 for event ids is not a secret."),
    "V11.6.1": (M, "RSA 3072 key generation by rcgen/aws-lc; RS256 signatures; ECDHE X25519 and X25519MLKEM768 in TLS."),
    # V12 Secure Communication
    "V12.1.1": (M, "TLS 1.3 only by default; TLS 1.2 only by explicit config (tests/tls.rs)."),
    "V12.1.2": (M, "rustls offers only modern AEAD suites; TLS 1.3 suites preferred; post-quantum key exchange preferred (SECURITY.md, TLS policy)."),
    "V12.1.3": (NA, "No mTLS client certificates are accepted."),
    "V12.2.1": (M, "All outbound connections are HTTPS (https:// required in config); no fallback to plain HTTP (tests/tls.rs)."),
    "V12.2.2": (D, "The GUI is not an external service. Behind the proxy, Traefik serves a publicly trusted certificate."),
    "V12.3.1": (D, "Outbound: TLS always. Inbound GUI: local mode only on loopback, reached through an SSH tunnel; proxy mode: run Traefik on the same host, or encrypt the hop (WireGuard/IPsec) when it crosses the network (docs/security/README.md)."),
    "V12.3.2": (M, "Certificates are validated against the system trust store (rustls-platform-verifier); untrusted and wrong-host certificates are refused (tests/tls.rs)."),
    "V12.3.3": (D, "Same as V12.3.1: there are no other internal HTTP services."),
    "V12.3.4": (D, "Same as V12.3.1."),
    # V13 Configuration
    "V13.1.1": (M, "SECURITY.md 'What runs where' and docs/security/README.md (communications): AFAS REST, login.microsoftonline.com, graph.microsoft.com, the optional webhook URL, the GUI listener."),
    "V13.2.1": (M, "Every outbound call is authenticated: AFAS token, Entra certificate (or secret), webhook HMAC."),
    "V13.2.2": (M, "Runs as an unprivileged system user with hardened systemd units (ProtectSystem=strict, no capabilities); least-privilege Graph permissions per module."),
    "V13.2.3": (M, "No default credentials: the installer creates a new key; tokens come from AFAS/Entra."),
    "V13.2.4": (M, "Outbound destinations are an allowlist in the locked config; nextLink and redirects to other hosts are refused."),
    "V13.2.5": (M, "Same as V13.2.4."),
    "V13.3.1": (D, "Secrets are never in the config: AFAS token and webhook secret from an environment variable or a 0600 file, the Entra key in a 0600 file, all ownership-checked. Provide them from your secret store (Ansible Vault, Semaphore secrets) as documented."),
    "V13.3.2": (M, "Secret files must be 0600 and owned by the service user or root, or the run stops (state::check_private_file)."),
    "V13.4.1": (M, "Only a static binary is installed; no source control metadata."),
    "V13.4.2": (M, "Release build; no debug endpoints; log level from RUST_LOG, default info."),
    "V13.4.3": (M, "No directory listings: only fixed routes."),
    "V13.4.4": (M, "TRACE and other methods answer 405 (tests/web.rs only_get_and_post_are_answered)."),
    "V13.4.5": (M, "No API docs or monitoring endpoints beyond /health, which only returns 'ok'."),
    # V14 Data Protection
    "V14.1.1": (M, "docs/security/DATA-AND-LOGGING.md (classification)."),
    "V14.1.2": (M, "docs/security/DATA-AND-LOGGING.md (protection per class)."),
    "V14.2.1": (M, "Session ids only in cookies, secrets only in bodies and headers. The one-time login link carries a single-use, 15-minute code in its URL by design; it is not a session token, is replaced on use, and Referrer-Policy: no-referrer keeps it from leaking (docs/security/README.md)."),
    "V14.2.2": (M, "Cache-Control: no-store on every response."),
    "V14.2.3": (M, "No trackers, analytics or third-party resources (CSP default-src 'none')."),
    "V14.2.4": (M, "docs/security/DATA-AND-LOGGING.md: retention, logging and access rules; reports contain employee numbers, not names; the first sign-in code is never logged or stored (tests/modules.rs ...never_logs_it)."),
    "V14.3.1": (M, "Sign-out sends Clear-Site-Data: \"cache\", \"cookies\", \"storage\" and expires the cookie."),
    "V14.3.2": (M, "Cache-Control: no-store."),
    "V14.3.3": (M, "Browser storage holds only the session cookie."),
    # V15 Secure Coding and Architecture
    "V15.1.1": (M, "SECURITY.md 'Updating dependencies': remediation times by severity; Dependabot and cargo-deny/cargo-audit in CI."),
    "V15.1.2": (M, "CycloneDX SBOM with every release (release workflow); Cargo.lock pinned; cargo-deny allows crates.io only."),
    "V15.1.3": (M, "docs/security/README.md (availability): sync runs, payload dumps, test runs and module runs; how they are limited."),
    "V15.2.1": (M, "cargo-deny and cargo-audit fail CI on any known vulnerability, unmaintained or yanked crate."),
    "V15.2.2": (M, "One run at a time, call caps, body caps (AFAS 128 MiB, provisioning logs and Graph pages 32 MiB, others 1 MiB), row cap, page caps, Retry-After cap."),
    "V15.2.3": (M, "The release contains only the binary, the installer, docs and licences; tests and fuzzers are not shipped."),
    "V15.3.1": (M, "Reports contain employee numbers and reasons, not names; the GUI shows only the fields it needs."),
    "V15.3.2": (M, "The HTTP client follows no redirects (http::build_client)."),
    "V15.3.3": (M, "Settings forms accept only the defined fields of their section; locked keys are refused (web::post_settings)."),
    "V15.3.4": (M, "The client IP is not taken from headers; proxy mode trusts only the connection's source address."),
    "V15.3.5": (M, "Rust's static types; strict equality."),
    "V15.3.6": (NA, "No JavaScript."),
    "V15.3.7": (M, "Query and form parameters are read separately; the CSRF token is only taken from the form body."),
    # V16 Security Logging and Error Handling
    "V16.1.1": (M, "docs/security/DATA-AND-LOGGING.md (log inventory)."),
    "V16.2.1": (M, "Audit and access log lines carry UTC time, user or actor, action, target and detail (web::audit, records::AccessEntry)."),
    "V16.2.2": (D, "Timestamps are UTC (RFC 3339 with Z); keep the host clock synchronised (NTP/chrony)."),
    "V16.2.3": (M, "Logs go only to the documented places: journald (stdout/stderr), audit.log, access.log, last-report.json."),
    "V16.2.4": (M, "JSON Lines and JSON; journald for the process log."),
    "V16.2.5": (M, "Never logged: tokens, keys, secrets, first sign-in codes; reports carry employee numbers, not names (tests: client secret never in output, pass never logged)."),
    "V16.3.1": (M, "Sign-in, refused sign-in, sign-out and expired sessions are in audit.log (tests/web.rs)."),
    "V16.3.2": (M, "Refused sessions and refused form tokens are logged."),
    "V16.3.3": (M, "Safety stops, module stops and refused form tokens are recorded (report, audit.log)."),
    "V16.3.4": (M, "TLS, sign-in and Graph failures end up in the report and the process log with the cause."),
    "V16.4.1": (M, "Log lines are JSON-encoded (serde_json), so newlines and control characters cannot forge entries."),
    "V16.4.2": (D, "Log files are 0600 in a 0700 directory owned by the service user. Ship them to a separate system for tamper resistance (V16.4.3)."),
    "V16.4.3": (D, "Forward journald and the JSON log files to your SIEM or log server (e.g. Graylog); documented in docs/security/DATA-AND-LOGGING.md."),
    "V16.5.1": (M, "No stack traces: errors are values (unwrap/expect/panic denied in production code); messages name the cause, never secrets."),
    "V16.5.2": (M, "External failures stop safely: nothing is uploaded on AFAS errors, retries with backoff, a failed run is repaired by the next one."),
    "V16.5.3": (M, "Fail closed: any validation or threshold failure means nothing is sent; modules change nothing above their maximum; the GUI is off when the config cannot be read."),
}


def official_list(source: str | None) -> list[dict]:
    """The official ASVS 5.0.0 requirements, checked against the pinned SHA-256."""
    if source:
        data = open(source, "rb").read()
    else:
        with urllib.request.urlopen(ASVS_URL, timeout=60) as r:  # noqa: S310 (fixed https URL)
            data = r.read()
    digest = hashlib.sha256(data).hexdigest()
    if digest != ASVS_SHA256:
        sys.exit(f"ASVS list checksum mismatch: {digest}, expected {ASVS_SHA256}")
    return list(csv.DictReader(io.StringIO(data.decode("utf-8"))))


def assess(official: list[dict]) -> list[dict]:
    rows = [r for r in official if r["L"] in ("1", "2")]
    out, missing = [], []
    for r in rows:
        rid, sec = r["req_id"], r["section_id"]
        if rid in R:
            status, ev = R[rid]
        elif sec in NA_SECTIONS:
            status, ev = NA, NA_SECTIONS[sec]
        else:
            missing.append(rid)
            continue
        out.append(
            {
                "req_id": rid,
                "level": "L" + r["L"],
                "chapter": r["chapter_name"],
                "requirement": r["req_description"],
                "status": status,
                "evidence": ev,
            }
        )
    if missing:
        sys.exit(f"not assessed: {', '.join(missing)}")
    extra = sorted(set(R) - {x["req_id"] for x in out})
    if extra:
        sys.exit(f"assessed ids that are not Level 1 or 2 requirements: {extra}")
    return out


def render(out: list[dict]) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=list(out[0].keys()), lineterminator="\r\n")
    w.writeheader()
    w.writerows(out)
    return buf.getvalue()


def _read(pattern: str) -> str:
    return "".join(open(f, encoding="utf-8").read() for f in sorted(glob.glob(pattern, recursive=True)))


def check_references(out: list[dict]) -> list[str]:
    """Every file, test and code symbol named in the evidence and the security documents
    must exist."""
    src = _read("src/**/*.rs")
    tests = _read("tests/**/*.rs")
    problems = []
    path_re = re.compile(
        r"(?:docs/[\w/.-]+\.(?:md|csv|py)|\b[A-Z][A-Z-]+\.md|src/[\w/]+\.rs|tests/[\w/]+\.rs"
        r"|fuzz/[\w/.-]+|\.github/[\w/.-]+\.yml|\bdeny\.toml|\.secrets\.baseline)"
    )
    for x in out:
        ev, rid = x["evidence"], x["req_id"]
        for f in path_re.findall(ev):
            f = f.rstrip(".")
            if not (os.path.exists(f) or os.path.exists(os.path.join("docs/security", f))):
                problems.append(f"{rid}: file {f} does not exist")
        # "tests/web.rs some_test_name" or "tests/web.rs some_prefix..." (prefix match)
        for name, dots in re.findall(r"tests/\w+\.rs ([a-z_][a-z0-9_]*)(\.\.\.)?", ev):
            pat = r"fn " + re.escape(name) + ("" if dots else r"\b")
            if not re.search(pat, tests):
                problems.append(f"{rid}: test {name}{dots} does not exist")
        for name, dots in re.findall(r"graph_client::([a-z_][a-z0-9_]*)(\.\.\.)?", ev):
            if not re.search(r"fn " + re.escape(name), tests):
                problems.append(f"{rid}: test {name} does not exist")
        for mod, item in re.findall(
            r"\b(web|graph|joiner|leaver|records|settings|model|state|config|http|entra|install|webhook|roles)::(?:[A-Z]\w*::)?(\w+)",
            ev,
        ):
            pat = rf"(?:fn|struct|enum|const|static|trait|type) {re.escape(item)}\b"
            if not re.search(pat, src):
                problems.append(f"{rid}: code {mod}::{item} does not exist")
    # Relative links in the security documents.
    for md in sorted(glob.glob("docs/security/**/*.md", recursive=True)) + ["SECURITY.md"]:
        text = open(md, encoding="utf-8").read()
        for link in re.findall(r"\]\(([^)#:]+)(?:#[^)]*)?\)", text):
            target = os.path.normpath(os.path.join(os.path.dirname(md), link))
            if not os.path.exists(target):
                problems.append(f"{md}: link {link} does not resolve")
    return problems


def main(argv: list[str]) -> None:
    check = "--check" in argv
    source = argv[argv.index("--source") + 1] if "--source" in argv else None
    out = assess(official_list(source))
    text = render(out)
    from collections import Counter

    c = Counter(x["status"] for x in out)
    print(f"{len(out)} requirements: " + ", ".join(f"{k} {v}" for k, v in sorted(c.items())))
    problems = check_references(out)
    if check:
        committed = open(OUT, encoding="utf-8", newline="").read() if os.path.exists(OUT) else ""
        if committed != text:
            problems.append(f"{OUT} is out of date: run python3 docs/security/asvs_assessment.py")
        for p in problems:
            print("FAIL", p)
        if problems:
            sys.exit(1)
        print("evidence: CSV up to date, every reference resolves")
        return
    with open(OUT, "w", encoding="utf-8", newline="") as f:
        f.write(text)
    for p in problems:
        print("WARN", p)


if __name__ == "__main__":
    main(sys.argv[1:])
