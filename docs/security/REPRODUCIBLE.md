# Reproducing a release binary

A release binary can be rebuilt bit for bit. What is fixed:

- **Toolchain:** `rust-toolchain.toml` (Rust 1.97.0, target `x86_64-unknown-linux-musl`).
- **Dependencies:** `Cargo.lock`, built with `--locked`.
- **C compiler:** aws-lc-sys compiles C code with `musl-gcc`. The release uses GCC 13.3 from
  Ubuntu 24.04 (`musl-tools`).
- **Paths:** the release build maps `$HOME/.cargo` to `/cargo` and the source directory to
  `/build` (`--remap-path-prefix`). The build directory and user therefore do not matter.

## Rebuild

```bash
docker run --rm -v "$PWD":/src -w /src ubuntu:24.04 bash -c '
  apt-get update && apt-get install -y --no-install-recommends curl ca-certificates gcc musl-tools
  curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain none
  . "$HOME/.cargo/env"
  rustup toolchain install 1.97.0 --profile minimal --target x86_64-unknown-linux-musl
  export RUSTFLAGS="--remap-path-prefix=$HOME/.cargo=/cargo --remap-path-prefix=$PWD=/build"
  cargo build --release --locked --target x86_64-unknown-linux-musl
  sha256sum target/x86_64-unknown-linux-musl/release/afas-entra-sync'
```

Compare the hash with `afas-entra-sync-linux-x86_64.sha256` from the release. If it differs,
`diffoscope` shows where.

Releases up to and including 0.10.0 were built without the path mapping. They can only be
rebuilt with `CARGO_HOME=/root/.cargo` and the toolchain of that day (1.97.0).
