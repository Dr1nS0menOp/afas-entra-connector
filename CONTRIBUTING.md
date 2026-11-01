# Contributing

Thanks for helping. This tool changes user accounts in production directories, so the bar
is high: no change without tests, and safety behaviour never gets weaker by default.

## Before you open a pull request

```
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo audit
```

- Add or update tests for every behaviour change. For anything in `plan.rs`, `model.rs`,
  `entra.rs` or `tls.rs`, include the exact boundary (off-by-one) cases.
- Keep `#![forbid(unsafe_code)]`. New dependencies need a reason and a permissive license
  compatible with Apache-2.0 (MIT, Apache-2.0, BSD, ISC, Unicode, Zlib); regenerate
  `THIRD-PARTY-LICENSES.txt` when dependencies change.
- Code, messages and docs are in English. Never put real tenant IDs, domains, employee
  data or secrets in code, tests, issues or pull requests.

## Security issues

Do not open a public issue. See `SECURITY.md`.

## License

By contributing you agree that your contributions are licensed under the Apache License,
Version 2.0 (see `LICENSE`), as described in section 5 of that license.
