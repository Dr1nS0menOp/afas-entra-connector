# Changelog

All notable changes. Versions follow [Semantic Versioning](https://semver.org/); before
1.0 a minor version may change configuration.

## 0.9.3 – 2026-11-01

Security assurance: self-assessed against **OWASP ASVS 5.0 Level 2** (all 253 Level 1 and 2
requirements, none unmet) and prepared for the **OpenSSF Best Practices** badge and
**Scorecard**. Evidence in `docs/security/`.

- **Fix (found by fuzzing):** an AFAS date with a non-ASCII character in its time part
  (e.g. `2024-01-01T00:00:0€`) crashed the whole run. It is now an ordinary data error
  for that one record.
- **GUI sign-in and sessions** (ASVS V3, V6, V7, V14, V16):
  - every sign-in gets its own random session; sessions end after 30 minutes without
    activity and after 8 hours; at most 20 at once;
  - the login link works once and expires after 15 minutes; a new one replaces it in
    `gui-login-url`;
  - cookie `__Host-afas_gui_session` with `Secure`, `HttpOnly`, `SameSite=Strict`;
  - "Sign out" on every page and "Sign out all sessions" on the GUI page, with
    `Clear-Site-Data`;
  - sign-in, refused sign-in, refused session, refused form token and sign-out are written
    to `audit.log`;
  - `Strict-Transport-Security` header; JSON downloads declare their charset.
- **No own cryptography:** the webhook HMAC now comes from AWS-LC (the library rustls
  already uses) instead of an own implementation.
- **No panics in production code:** `unwrap`, `expect` and `panic!` are denied by the
  compiler outside tests.
- The installer copies `/proc/self/exe`, the program that is actually running.
- Module certificates in the docs are valid for 365 days (was 730), in line with SECURITY.md.
- **Supply chain and CI:** `deny.toml` (RustSec, licences, crates.io only), CodeQL (Rust
  and Actions), OpenSSF Scorecard, secret scanning with a reviewed baseline, zizmor for
  workflows, shellcheck, a fuzz smoke test, Dependabot; every action pinned to a commit.
  Releases are built by GitHub Actions with a CycloneDX SBOM and signed build provenance
  (`gh attestation verify`).
- Fuzzing: `fuzz/` with four cargo-fuzz targets (AFAS response, configuration, small
  parsers, GUI request handler).

## 0.9.2 – 2026-11-01

Bug fixes from a review of the modules. No configuration changes are needed, but see the
two new configuration checks.

- **Graph:** a POST is no longer repeated after a network error or a 5xx, because Graph
  may already have carried it out (a second sign-in code or mail). 429 and 401 are still
  retried.
- **New hires (joiners):** an existing, usable Temporary Access Pass is never replaced
  (reported as a note); an expired or used one is removed first; when the outcome of
  creating one is unknown, any pass that appeared is removed; a manager who has left
  never receives the code (the fixed address is used instead); the start time is right
  on days the clocks change.
- **Access log:** a failure to write it is now a failure (exit 42), not silently ignored.
- **Departing employees (leavers):** the automatic reply is HTML-escaped and keeps its
  line breaks.
- **Configuration checks:** `roles.keep_leavers_days` must be smaller than
  `policy.leaver_lookback_days`, and the leaver module needs a lookback of at least 1;
  otherwise those actions would never happen.
- **Exceptions:** the CLI now checks that the group is in the role rules, like the GUI;
  both check the staff category prefix of the employee number.
- **Webhook:** a comparison older than 7 days counts as a new baseline, so switching the
  webhook on after a long pause does not send stale events.
- `joiner.sender` may not contain `/ ? # % \` (it is used in a URL path).
- Tests: the Graph client (retries, Retry-After cap, token refresh, paging, host check,
  network errors) and every decision rule of the modules at its boundaries. A mutation
  run on the module code went from 82 to 4 missed mutants, all equivalent
  (`MUTATION-REPORT.md`). The old test for unsafe groups passed for another reason and
  now checks the real refusal.

## 0.9.1 – 2026-11-01

- Plain language with the HR term in brackets everywhere: new hires (joiners), job changes
  (movers), departing employees (leavers), first sign-in code (Temporary Access Pass),
  conflicting groups (segregation of duties), staff category (population), skipped
  records (exclusions), test run (dry-run). Word list in README and guide.
- **Fix:** GUI settings pages showed keys left out of the config file as empty or off;
  saving a module page unchanged could switch off "sign out everywhere". The GUI now shows
  the value in use and treats a default as no change.

## 0.9.0 – 2026-11-01

Optional modules, each with its own app registration, maximum per run and test run:

- **Roles and licences:** group membership from HR data, licences through group-based
  licensing, conflicting groups (segregation of duties), time-limited exceptions.
- **New hires:** first sign-in code (Temporary Access Pass) mailed to the manager.
- **Departing employees:** sign out everywhere and an automatic reply.
- **Webhook:** signed (HMAC-SHA256) events for new hires, job changes and departing
  employees, with a send queue and retries.
- **Access log** with `report` (JSON/CSV) and GUI pages; `exception` command.
- Exit codes 21 (module stopped itself) and 42 (module failed).

## 0.8.0 – 2026-11-01

- One-step installer without Ansible: `install.sh` / `afas-entra-sync install`, `uninstall`.

## 0.7.0 – 2026-11-01

- TLS 1.3 only by default with post-quantum key exchange (X25519MLKEM768) preferred,
  `require` mode, `check-tls` command. Security review (`SECURITY.md`).
- Published under the Apache License 2.0.
