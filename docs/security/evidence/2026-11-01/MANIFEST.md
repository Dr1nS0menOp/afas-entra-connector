# Evidence 2026-11-01 (version 0.9.3)

Raw output of the scans summarised in [../../SCAN-REPORT.md](../../SCAN-REPORT.md). Local
paths are replaced by `.`; nothing else is edited. Check a file with `sha256sum -c` against
the column below, or `sha256sum -c SHA256SUMS`.

| File | Tool | Command | Result | SHA-256 |
| --- | --- | --- | --- | --- |
| `cargo-audit.json` | cargo-audit 0.22.2, RustSec database commit 2295466 (2026-10-30, 1,395 advisories) | `cargo audit --json` | 0 vulnerabilities, 0 warnings, 303 crates | `c80c047e1bec3ebd…` |
| `cargo-deny.txt` | cargo-deny 0.20.2 with deny.toml | `cargo deny check` | advisories ok, bans ok, licenses ok, sources ok (duplicate-version warnings are informational) | `12e47fb2791b3488…` |
| `semgrep.json` | semgrep 1.183.0, 252 rules from semgrep-rules (rust, generic/secrets, bash, yaml/github-actions) | `semgrep scan --json --config <rules> src install.sh deploy .github fuzz/fuzz_targets` | 0 findings on 42 files (2 triaged in code with nosemgrep and a reason) | `904975d6f03808ce…` |
| `zizmor.json` | zizmor 1.31.1, persona pedantic | `zizmor --offline --persona=pedantic --format=json .github/workflows/` | 0 findings | `4f53cda18c2baa0c…` |
| `shellcheck.txt` | shellcheck 0.11.0 | `shellcheck -S style install.sh deploy/ansible/checkmk/afas_entra_sync` | 0 findings | `773ec1574eac07f8…` |
| `clippy.txt` | clippy, rustc 1.97.0 | `cargo clippy --all-targets -- -D warnings` | 0 warnings | `17538dbd25ec4b18…` |
| `tests.txt` | cargo test, rustc 1.97.0 | `cargo test --no-fail-fast` | 218 passed, 0 failed | `d21ce9402a9599cb…` |
| `fuzzing.txt` | cargo-fuzz 0.13.2, libFuzzer with AddressSanitizer, nightly 2026-10-27 | `cargo +nightly fuzz run -O <target> ...` | 1 crash in run 1 (fixed in 0.9.3); runs 2 and 3 clean | `0f89f6295e1e47b8…` |
| `fuzz-crash-afas_response.bin` | cargo-fuzz | `(input written by libFuzzer)` | The input that crashed the date parser; also in fuzz/corpus/afas_response as a regression seed | `bc17cecd4be2e922…` |
| `mutation-testing.txt` | cargo-mutants | `cargo mutants -f <files> -C --test=<suite>` | Modules and Graph client: 82 missed, then 4 (equivalent); GUI sessions: 1 missed, then 0 | `fff72d950a458bed…` |
| `sbom-0.9.3.cdx.json` | cargo-cyclonedx 0.5.7 | `cargo cyclonedx --format json` | CycloneDX 1.3, 212 components | `4147adede48b2291…` |

The ASVS assessment itself is checked in CI (`python3 docs/security/asvs_assessment.py --check`)
against the official requirement list, pinned to the OWASP ASVS `v5.0.0_release` tag by
SHA-256.
