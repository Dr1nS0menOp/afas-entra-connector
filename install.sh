#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# afas-entra-sync installer.
#
#   sudo ./install.sh                 # asks what it needs
#   sudo ./install.sh --help          # all options (unattended install with flags)
#
# Checks the binary next to this script against its SHA-256 file, then runs
# `afas-entra-sync install`, which does the actual work. Safe to run again.
set -eu

cd "$(dirname "$0")"
BIN=afas-entra-sync-linux-x86_64

fail() { echo "install.sh: $*" >&2; exit 1; }

[ "$(uname -s)" = "Linux" ] || fail "Linux only"
case "$(uname -m)" in
  x86_64 | amd64) ;;
  *) fail "only an x86_64 binary is provided; build from source for $(uname -m)" ;;
esac
[ -f "$BIN" ] || fail "$BIN not found next to this script"
[ -f "$BIN.sha256" ] || fail "$BIN.sha256 not found next to this script"
command -v sha256sum >/dev/null 2>&1 || fail "sha256sum is required"
sha256sum --quiet -c "$BIN.sha256" || fail "checksum mismatch: the binary is damaged or not the released one; do not install it"
chmod 0755 "$BIN"

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
  exec "./$BIN" install --help
fi
exec "./$BIN" install "$@"
