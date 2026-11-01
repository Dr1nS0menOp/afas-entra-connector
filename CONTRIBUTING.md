# Contributing

Thanks for helping. This tool changes user accounts in production directories, so the bar
is high: no change without tests, and safety behaviour never gets weaker by default.

## How to contribute

- **Bugs and ideas**: open an issue on GitHub. Say what you did, what you expected and
  what happened; leave out real tenant IDs, names and employee data.
- **Changes**: fork the repository, make a branch, open a pull request against `main`.
  CI must pass (tests, lint, dependency policy, secret scan, CodeQL) and a maintainer
  reviews every pull request before it is merged.
- **Security issues**: not in an issue; see `SECURITY.md`.

## Before you open a pull request

```
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo deny check
cargo audit
```

- **Test policy**: every new feature and every bug fix comes with automated tests in the
  same pull request; a bug fix includes a test that fails without the fix. Pull requests
  without tests are not merged.
- Add or update tests for every behaviour change. For anything in `plan.rs`, `model.rs`,
  `entra.rs` or `tls.rs`, include the exact boundary (off-by-one) cases.
- Coding standard: `rustfmt` formatting, no clippy warnings, no `unwrap`, `expect` or
  `panic!` in production code (enforced by the compiler), errors as values with a clear
  message.
- Keep `#![forbid(unsafe_code)]`. New dependencies need a reason and a permissive license
  compatible with Apache-2.0 (MIT, Apache-2.0, BSD, ISC, Unicode, Zlib); regenerate
  `THIRD-PARTY-LICENSES.txt` when dependencies change.
- Code, messages and docs are in English. Never put real tenant IDs, domains, employee
  data or secrets in code, tests, issues or pull requests.

## License

By contributing you agree that your contributions are licensed under the Apache License,
Version 2.0 (see `LICENSE`), as described in section 5 of that license.
