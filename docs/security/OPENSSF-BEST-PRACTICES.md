# OpenSSF Best Practices badge: answers

Answers for the **passing** level of the [OpenSSF Best Practices
badge](https://www.bestpractices.dev/criteria/0), ready to enter on bestpractices.dev
after the repository is public. Replace `<repo>` with the GitHub URL. Last reviewed
2026-11-01 (version 0.9.3).

Status: **Met** = true today; **On publish** = true as soon as the repository is public on
GitHub with issues and private vulnerability reporting switched on; **N/A** = does not
apply.

## Basics

| Criterion | Level | Status | Justification |
| --- | --- | --- | --- |
| description_good | MUST | Met | README, first paragraph: what the program does and what problem it solves |
| interact | MUST | On publish | README (install, download); issues for feedback; CONTRIBUTING.md |
| contribution | MUST | Met | `<repo>/blob/main/CONTRIBUTING.md`: issues and pull requests against `main`, CI and review |
| contribution_requirements | SHOULD | Met | CONTRIBUTING.md: coding standard, test policy, licences of dependencies |
| floss_license | MUST | Met | Apache-2.0 |
| floss_license_osi | SUGGESTED | Met | Apache-2.0 is OSI-approved |
| license_location | MUST | Met | `LICENSE` in the repository root |
| documentation_basics | MUST | Met | README, docs/GUIDE.md, docs/MODULES.md |
| documentation_interface | MUST | Met | README (commands, exit codes, configuration), example config, docs/MODULES.md (webhook format, report fields) |
| sites_https | MUST | On publish | GitHub (HTTPS only) |
| discussion | MUST | On publish | GitHub issues and pull requests |
| english | SHOULD | Met | Code, documentation and messages in English |
| maintained | MUST | Met | Active development; releases 0.7.0 to 0.9.3 in 2026 |

## Change control

| Criterion | Level | Status | Justification |
| --- | --- | --- | --- |
| repo_public | MUST | On publish | `<repo>` |
| repo_track | MUST | Met | git |
| repo_interim | MUST | Met | Every change is a commit; releases are tags |
| repo_distributed | SUGGESTED | Met | git |
| version_unique | MUST | Met | Cargo.toml version, `--version` |
| version_semver | SUGGESTED | Met | Semantic Versioning (CHANGELOG.md) |
| version_tags | SUGGESTED | Met | `v0.7.0` … `v0.9.3` |
| release_notes | MUST | Met | CHANGELOG.md, per release, human-written |
| release_notes_vulns | MUST | N/A | No publicly known vulnerabilities so far; SECURITY.md commits to naming them |

## Reporting

| Criterion | Level | Status | Justification |
| --- | --- | --- | --- |
| report_process | MUST | On publish | GitHub issues; CONTRIBUTING.md |
| report_tracker | SHOULD | On publish | GitHub issues |
| report_responses | MUST | On publish | Acknowledge every issue; no reports yet |
| enhancement_responses | SHOULD | On publish | Same |
| report_archive | MUST | On publish | GitHub issues are public and searchable |
| vulnerability_report_process | MUST | Met | SECURITY.md, "Reporting a vulnerability" |
| vulnerability_report_private | MUST | On publish | GitHub private vulnerability reporting (switch it on under Settings → Code security) |
| vulnerability_report_response | MUST | Met | SECURITY.md: response within 7 days |

## Quality

| Criterion | Level | Status | Justification |
| --- | --- | --- | --- |
| build | MUST | Met | `cargo build --release` |
| build_common_tools | SUGGESTED | Met | Cargo |
| build_floss_tools | SHOULD | Met | Rust toolchain, all FLOSS |
| test | MUST | Met | 218 automated tests (`cargo test`), documented in README and CONTRIBUTING.md, run in CI |
| test_invocation | SHOULD | Met | `cargo test` |
| test_most | SUGGESTED | Met | Unit, end-to-end against mock AFAS and Microsoft, property and fuzz tests; mutation testing (MUTATION-REPORT.md) |
| test_continuous_integration | SUGGESTED | Met | `.github/workflows/ci.yml` on every push and pull request |
| test_policy | MUST | Met | CONTRIBUTING.md, "Test policy" |
| tests_are_added | MUST | Met | Every change since 0.1.0 added tests (git history, CHANGELOG.md, MUTATION-REPORT.md) |
| tests_documented_added | SUGGESTED | Met | CONTRIBUTING.md |
| warnings | MUST | Met | `cargo clippy -D warnings` in CI; `unwrap`/`expect`/`panic` denied in production code |
| warnings_fixed | MUST | Met | CI fails on any warning |
| warnings_strict | SUGGESTED | Met | Warnings are errors; extra lints on panics |

## Security

| Criterion | Level | Status | Justification |
| --- | --- | --- | --- |
| know_secure_design | MUST | Met | Design documented in SECURITY.md (threat model) and docs/security/ (ASVS 5.0 L2 self-assessment) |
| know_common_errors | MUST | Met | docs/security/asvs-5.0-L2.csv maps the common error classes to their countermeasures |
| crypto_published | MUST | Met | TLS 1.3, ML-KEM, X25519, AES-GCM, RSA, SHA-256, HMAC; docs/security/CRYPTO-INVENTORY.md |
| crypto_call | SHOULD | Met | All cryptography via rustls, aws-lc-rs, jsonwebtoken, rcgen; none implemented in this project |
| crypto_floss | MUST | Met | All libraries are FLOSS |
| crypto_keylength | MUST | Met | RSA 3072, 256-bit secrets, TLS 1.3 groups; TLS 1.2 only by explicit config |
| crypto_working | MUST | Met | No broken algorithms (CRYPTO-INVENTORY.md) |
| crypto_weaknesses | SHOULD | Met | SHA-1 only as the `x5t` certificate identifier Entra requires, next to SHA-256 `x5t#S256`; not a security function |
| crypto_pfs | SHOULD | Met | TLS 1.3 (ECDHE / ML-KEM hybrid) |
| crypto_password_storage | MUST | N/A | No passwords stored |
| crypto_random | MUST | Met | getrandom (OS CSPRNG) for every secret |
| delivery_mitm | MUST | Met | GitHub releases over HTTPS; SHA-256 checksums; signed build provenance |
| delivery_unsigned | MUST | Met | `install.sh` and Ansible check the SHA-256 of the binary, which comes from the same HTTPS release; provenance verifiable with `gh attestation verify` |
| vulnerabilities_fixed_60_days | MUST | Met | No known vulnerabilities; `cargo deny`/`cargo audit` clean (SCAN-REPORT.md) |
| vulnerabilities_critical_fixed | SHOULD | Met | SECURITY.md: critical within 7 days |
| no_leaked_credentials | MUST | Met | Secret scan of all history: only test keys and published test vectors (`.secrets.baseline`, SCAN-REPORT.md) |

## Analysis

| Criterion | Level | Status | Justification |
| --- | --- | --- | --- |
| static_analysis | MUST | Met | clippy, semgrep, CodeQL (Rust, Actions) |
| static_analysis_common_vulnerabilities | SUGGESTED | Met | CodeQL security-extended, semgrep security rules |
| static_analysis_fixed | MUST | Met | All findings fixed or triaged (SCAN-REPORT.md) |
| static_analysis_often | SUGGESTED | Met | CodeQL on every push and pull request |
| dynamic_analysis | SUGGESTED | Met | cargo-fuzz (4 targets, libFuzzer with sanitizer instrumentation) before release, plus a fuzz smoke test in CI |
| dynamic_analysis_unsafe | SUGGESTED | N/A | Rust without `unsafe` |
| dynamic_analysis_enable_assertions | SUGGESTED | Met | Fuzz targets assert invariants (escaping, no unauthenticated access) |
| dynamic_analysis_fixed | MUST | Met | The fuzz finding of 2026-11-01 (date parser panic) is fixed with regression tests |
