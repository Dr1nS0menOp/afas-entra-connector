# Evidence 2026-11-01 (version 0.10.0)

Raw output of the scans of version 0.10.0, summarised in [../../SCAN-REPORT.md](../../SCAN-REPORT.md).
Local paths are replaced by `.`; nothing else is edited. Check with `sha256sum -c SHA256SUMS`.
The earlier scans of 0.9.3, including the full fuzzing campaign and mutation testing, are in
[../2026-11-01](../2026-11-01/MANIFEST.md).

| File | Tool | Command | Result | SHA-256 |
| --- | --- | --- | --- | --- |
| `cargo-audit.json` | cargo-audit 0.22.2, RustSec database commit 2295466 (2026-10-30, 1,395 advisories) | `cargo audit --json` | 0 vulnerabilities, 0 warnings, 303 crates | `f7c670f96fbac8a8…` |
| `cargo-deny.txt` | cargo-deny 0.20.2 with deny.toml | `cargo deny check` | advisories ok, bans ok, licenses ok, sources ok | `06c0370d7a6e4261…` |
| `semgrep.json` | semgrep 1.183.0, semgrep-rules (rust, generic/secrets, bash, yaml/github-actions) | `semgrep scan --json --config <rules> src install.sh deploy .github fuzz/fuzz_targets` | 0 findings on 44 files (3 triaged in code with nosemgrep and a reason) | `acafe8a63a41dad7…` |
| `zizmor.json` | zizmor 1.31.1, persona pedantic | `zizmor --offline --persona=pedantic --format=json .github/workflows/` | 0 findings | `4f53cda18c2baa0c…` |
| `shellcheck.txt` | shellcheck 0.11.0 | `shellcheck -S style install.sh deploy/ansible/checkmk/afas_entra_sync` | 0 findings (empty output) | `e3b0c44298fc1c14…` |
| `clippy.txt` | clippy, rustc 1.97.0 | `cargo clippy --all-targets -- -D warnings` | 0 warnings | `82e3a36be77a77d4…` |
| `tests.txt` | cargo test, rustc 1.97.0 | `cargo test --no-fail-fast` | 238 passed, 0 failed | `291d3aa443391fb6…` |
| `fuzzing.txt` | cargo-fuzz 0.13.2, libFuzzer with AddressSanitizer, nightly 2026-10-27 | `cargo +nightly fuzz run -O gui_request -- -max_total_time=120` | 21,337 runs, clean (GUI handler, including the new health check route) | `d66df6d71378648d…` |
| `sbom-0.10.0.cdx.json` | cargo-cyclonedx 0.5.7 | `cargo cyclonedx --format json` | CycloneDX 1.3, 212 components | `6d9a578d68cd914d…` |
