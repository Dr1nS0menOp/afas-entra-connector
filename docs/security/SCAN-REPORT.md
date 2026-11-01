# Security scan report

Version 0.9.3, scanned 2026-11-01 on the release commit. Raw output of every scan, with
SHA-256 checksums: [evidence/2026-11-01](evidence/2026-11-01/MANIFEST.md). Toolchain: rustc 1.97.0 (stable),
nightly 1.101.0 for fuzzing. Every scan below also runs in CI (`.github/workflows/`), so
the next result is in the repository's Actions and Security tabs.

## Summary

| Scan | Tool | Result |
| --- | --- | --- |
| Known vulnerabilities in dependencies | cargo-audit 0.22.2, RustSec database (1,395 advisories) | 0 vulnerabilities, 0 warnings in 303 crates |
| Dependency policy | cargo-deny 0.20.2, `deny.toml` | advisories ok, bans ok, licences ok, sources ok |
| Static analysis (SAST) | semgrep 1.183.0, 252 official rules (Rust security, secrets, bash, GitHub Actions) | 0 open findings; 2 triaged as intended (below); 1 fixed |
| Static analysis (SAST) | CodeQL (Rust, Actions), `security-extended` | Runs in CI on GitHub; not available offline |
| Lint | clippy, warnings as errors; `unwrap`/`expect`/`panic` denied in production code | Clean |
| Secrets | detect-secrets 1.5.0, all tracked files and full git history | 0 secrets; 8 hits reviewed as false positives (`.secrets.baseline`) |
| CI workflows | zizmor 1.31.1, pedantic | 0 findings |
| Shell scripts | shellcheck 0.11.0, style level | Clean (`install.sh`, Checkmk check) |
| Dynamic analysis | cargo-fuzz 0.13.2 (libFuzzer, AddressSanitizer), 4 targets | 1 crash found and fixed; afterwards clean |
| Tests | `cargo test` | 218 passed, 0 failed |
| Mutation testing | cargo-mutants (modules, Graph client, GUI sessions) | 4 equivalent mutants remain (MUTATION-REPORT.md) |
| Browser check | Chromium (Playwright) against the GUI | `__Host-` cookie with Secure/HttpOnly/SameSite=Strict accepted over http://127.0.0.1; login link single-use; sign-out clears the cookie |
| Software bill of materials | cargo-cyclonedx 0.5.7 | CycloneDX 1.3, 212 components (attached to each release) |

## Fuzzing

| Target | What it feeds | Runs | Result |
| --- | --- | --- | --- |
| `afas_response` | Any AFAS response body through `parse_rows`, `check_schema`, `parse_row` | 1,013,895, then 7,058,722 after the fix | **Crash found**, fixed, then clean |
| `config` | Any configuration text, and any overrides on the example config | 123,330 | Clean |
| `small_parsers` | Dates, UPNs, AFAS token, Retry-After, form bodies, HTML escaping, Graph users, object ids | 2,159,850 and 1,758,108 | Clean; asserts escaping leaves no markup |
| `gui_request` | Any method, path, headers and body to the GUI, signed in and not | 46,062 and 36,207 | Clean; asserts no page answers 200 without sign-in |

## Findings and what was done

| # | Found by | Finding | Severity | Resolution |
| --- | --- | --- | --- | --- |
| 1 | cargo-fuzz | An AFAS date with a non-ASCII character in its time part (`2024-01-01T00:00:0€`) made `parse_afas_date` slice inside a UTF-8 character: the whole run crashed on one bad HR record | Medium (availability; one bad record stops provisioning) | Fixed: byte-level ASCII check; four regression tests; the crashing input is kept in the fuzz corpus |
| 2 | ASVS review | GUI: one fixed session per process, no timeouts, no sign-out; login link valid until restart | Medium | Fixed: per-sign-in sessions, 30 min idle / 8 h maximum, sign-out, single-use 15-minute link (tests in `tests/web.rs`) |
| 3 | ASVS review | Session cookie without `Secure` and `__Host-` prefix | Low | Fixed |
| 4 | ASVS review | Sign-in events not in the audit log | Low | Fixed: sign-in, refusals, sign-out logged |
| 5 | OpenSSF `crypto_call` | Own HMAC-SHA-256 implementation for the webhook | Low (it was correct and tested) | Replaced by AWS-LC's HMAC |
| 6 | semgrep `current-exe` | Installer copied the file at `current_exe()`, which can change after start | Low | Installs `/proc/self/exe`; `current_exe()` remains only as the non-Linux fallback (annotated) |
| 7 | semgrep, zizmor | CI actions not pinned to a commit; checkout kept credentials | Medium (supply chain) | All actions pinned to full commit hashes; `persist-credentials: false`; minimal permissions; concurrency limits |
| 8 | ASVS review | No HSTS header; JSON download without charset | Low | Added |
| 9 | clippy (strict) | One `expect` in production code | Info | Removed; panicking calls are now denied by the compiler |

## Triaged as intended

| Tool | Location | Why it stays |
| --- | --- | --- |
| semgrep `current-exe` | `src/main.rs` | Fallback only when `/proc` is missing (the installer targets Linux) |
| semgrep `temp-dir` | `fuzz/fuzz_targets/gui_request.rs` | Fuzz harness, not shipped |
| detect-secrets | `tests/fixtures/*.pem` | Test-only keys (`tests/fixtures/README.md`) |
| detect-secrets | `tests/modules.rs`, `tests/module_rules.rs` | Published HMAC test vectors (RFC 4231) and reference values |
| detect-secrets | `docs/MODULES.md`, `.github/workflows/ci.yml` | The word "secret" next to a variable name |

## Not covered by these scans

- A penetration test by an independent party.
- CodeQL and OpenSSF Scorecard, which need the repository on GitHub; they run there.
- The deployment itself (SSH, Traefik, Authentik, log shipping): see the deployment
  conditions in [README.md](README.md).
