# Ansible deployment

Installs afas-entra-sync on a Linux host as the system user `afas-sync`, places a validated
configuration, and optionally runs the admin GUI as a hardened systemd service.

| Playbook | Does |
| --- | --- |
| `install-afas-entra-sync.yml` | User, directories, binary (checksum verified), AFAS token, config (validated with `check-config`), key permissions, GUI service |
| `run-afas-entra-sync.yml` | Runs a sync (`-e apply=true` to upload), shows the report, fails on any exit code other than 0 |
| `run-check-logs.yml` | Checks the provisioning logs of the last hour |

## Steps

1. Put the release binary and its checksum in `files/`:
   `files/afas-entra-sync-linux-x86_64` and `files/afas-entra-sync-linux-x86_64.sha256`
   (from a release, or build it: `cargo build --release --target x86_64-unknown-linux-musl`,
   then `sha256sum afas-entra-sync-linux-x86_64 > afas-entra-sync-linux-x86_64.sha256`).
2. Copy `vars.example.yml`, fill it in, and keep `afas_token` in a vault or your
   automation tool's secret store.
3. Adjust the AFAS field names in `templates/afas-entra-sync.toml.j2` to your GetConnector.
4. Run `install-afas-entra-sync.yml`, create the certificate (see `docs/GUIDE.md`), run it
   again, then `afas-entra-sync -c /etc/afas-entra-sync/config.toml check-tls`.
5. Schedule `run-afas-entra-sync.yml` (dry-run first, `apply=true` after review).

`checkmk/afas_entra_sync` is an optional Checkmk local check that reads the last report.
