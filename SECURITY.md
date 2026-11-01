# Security

Security design, hardening and verification of afas-entra-sync and the Ansible deployment
in `deploy/ansible`. Last reviewed 2026-11-01 (version 0.7.0).

## What runs where

| Component | Runs on | Talks to | Who controls TLS |
| --- | --- | --- | --- |
| afas-entra-sync (this tool) | Linux host (Ansible/Semaphore target) | AFAS REST, `login.microsoftonline.com`, `graph.microsoft.com` | This tool (`[tls]`, rustls + aws-lc-rs) |
| Microsoft Entra provisioning agent | Windows Server (domain-joined) | Microsoft cloud (outbound 443), domain controllers | Windows Schannel / .NET Framework |
| AFAS Profit Entra ID integration (groups) | AFAS Online (cloud) | Microsoft Graph | AFAS and Microsoft; nothing to install on your side |

The AFAS group integration is configured in Profit and talks to Microsoft from the
AFAS cloud. It has no component on your servers, so the Windows Server version does not
apply to it.

## Threat model (short)

| Threat | Control |
| --- | --- |
| Wrong or partial HR data disables or creates many accounts | Safety thresholds (min records, max drop, max invalid, max disables, max calls), dry-run, records with errors are never sent, no deletes |
| Eavesdropping or tampering on the network | TLS 1.3 only by default, post-quantum hybrid key exchange preferred, system trust store, no redirects followed |
| "Harvest now, decrypt later" of HR data | X25519MLKEM768 offered first; `post_quantum = "require"` refuses classical-only servers |
| Token or secret sent to the wrong host | AFAS, login and Graph addresses only in the config file (locked for the GUI), `https://` required, Graph `nextLink` only to the same host |
| Stolen secrets on disk | Token file and private key must be mode 0600 and owned by the service user or root, otherwise the run stops; certificate auth recommended over a client secret |
| Memory exhaustion by a broken or hostile endpoint | Response bodies capped (AFAS 128 MiB, logs 32 MiB, others 1 MiB), at most 1,000,000 rows, at most 200 log pages |
| GUI misuse by another local user or a web page in the admin's browser | GUI off by default; local mode needs the login link (file readable by the service user only) and a session cookie; Host header checked (DNS rebinding); CSRF token; strict CSP, no JavaScript |
| GUI misuse over the network | Non-local only behind a trusted proxy (Traefik) with the Authentik user header; everything audited |
| GUI weakens security settings | TLS policy, addresses, secrets, state and the GUI switch are locked; the GUI can turn itself off but never on |
| Compromised dependency | `Cargo.lock` pinned, `cargo audit` clean (0 advisories in 303 crates on 2026-11-01), `#![forbid(unsafe_code)]` |
| Tampered binary during deployment | `install.sh` and Ansible verify the SHA-256 checksum before installing |
| Installer leaves a half-configured host | Every answer is validated and the config is built and checked before anything is written; files are written atomically with final permissions |

## TLS policy

```toml
[tls]
min_version = "1.3"        # default; "1.2" only if an endpoint cannot do 1.3
post_quantum = "prefer"    # default; "require" refuses servers without ML-KEM
```

- **Versions:** TLS 1.3 only by default. TLS 1.0/1.1 are never possible.
- **Cipher suites:** TLS 1.3 AEAD suites only (AES-256-GCM, ChaCha20-Poly1305, AES-128-GCM).
  With `min_version = "1.2"`, only ECDHE with AEAD ciphers (no RSA key exchange, no CBC).
- **Key exchange, `prefer`:** X25519MLKEM768 (hybrid post-quantum), then X25519, secp384r1,
  secp256r1. If the server supports ML-KEM it is used; otherwise classical ECDHE.
- **Key exchange, `require`:** only X25519MLKEM768 and secp256r1MLKEM768. A server without
  ML-KEM is refused (the run stops with an error; nothing is sent).
- **Certificates:** checked against the operating system trust store.
- **Crypto library:** aws-lc-rs (AWS-LC). No OpenSSL.
- The `[tls]` section is locked: the GUI cannot weaken it.

### Check what is actually negotiated

Run this on the Linux host, before going live and after network changes:

```
afas-entra-sync -c /etc/afas-entra-sync/config.toml check-tls
```

It does a full handshake with AFAS, Entra login and Graph and reports per endpoint the TLS
version, cipher suite, key exchange group and whether it is post-quantum. Exit 0 = all
endpoints meet the policy, exit 60 = at least one does not.

Do not switch to `post_quantum = "require"` until `check-tls` shows
`"post_quantum_everywhere": true`. On 2026-11-01 neither Microsoft nor AFAS documents ML-KEM
support for these endpoints; `prefer` gives you post-quantum protection automatically as
soon as they add it.

A TLS-inspecting firewall or proxy (SSL/TLS decryption on a firewall) terminates TLS
itself; `check-tls` then shows the firewall's TLS, not the endpoint's. Exclude these three
hosts from decryption, or accept that the firewall decides the TLS level. Some inspection
engines fail on the larger ML-KEM handshake; `check-tls` will show that as a handshake error.

## Windows Server for the provisioning agent

- **Version:** Microsoft recommends Windows Server 2025 or 2022 for the Entra provisioning
  agent (Cloud Sync prerequisites). Entra Connect Sync supports Windows Server 2025 since
  February 2026, so the agent can share the Connect Sync server.
- **TLS 1.2 must stay enabled** on that server: Microsoft lists it as an installation
  requirement for the agent. Do not disable TLS 1.2 machine-wide there. TLS 1.3 is on by
  default in Windows Server 2022/2025 Schannel and is used where the endpoint supports it.
- **Post-quantum in Schannel:** Windows Server 2025 got hybrid ML-KEM groups
  (X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024) with the July 2026 cumulative
  update. They are off by default and are enabled through Group Policy (ECC Curve Order) or
  the TLS PowerShell cmdlets. Put X25519MLKEM768 first and keep curve25519 and nistP256
  after it, so connections fall back when the other side has no ML-KEM. Test on one
  server first: the setting applies to all Schannel traffic on that machine.
- Disable TLS 1.0/1.1 and weak ciphers machine-wide (Microsoft has removed them from Entra
  endpoints since 2022).
- Server Core is not supported for the agent. Use a gMSA for the agent service.

## Linux host

- The tool runs as the system user `afas-sync` (no shell, no home). Config and state
  directories are 0700; the token and private key 0600.
- The installer (`install`) writes the same hardened units for the sync, check-logs and GUI
  services; each scores 1.5 ("OK") on `systemd-analyze security`.
- The admin GUI runs as a hardened systemd service (`ProtectSystem=strict`, no
  capabilities, syscall filter, `MemoryDenyWriteExecute`, only the state directory
  writable). `systemd-analyze security` exposure: 1.5 ("OK").
- Signing in locally: open an SSH tunnel (`ssh -L 8080:127.0.0.1:8080 host`), then the link
  from `/var/lib/afas-entra-sync/gui-login-url`. The link is valid only while that server
  process runs; every restart creates a new one.
- Behind Traefik (`--trusted-proxy`), run Traefik on the same host or on a dedicated
  network segment: the hop between Traefik and the GUI is plain HTTP.
- Keep the GUI off when you do not need it (`gui_enabled: false`).

## Certificate for Entra

- Use certificate authentication, not a client secret. RSA 3072 or 4096 bits, SHA-256,
  valid for at most 1 year, private key generated on the host and never copied elsewhere.
- Application permissions: only `SynchronizationData-User.Upload` and
  `ProvisioningLog.Read.All`. No directory-wide write permissions.
- Renew in time; Entra refuses an expired certificate (exit 40).

## AFAS group integration

- It matches users on the UPN, so the UPN from AFAS must be the AD UPN (this tool sends
  exactly that UPN).
- Review the permissions AFAS asks for during consent under Enterprise applications, and
  check its sign-in logs. Its permissions are granted to the AFAS cloud, outside your
  control; limit who can change group mappings in Profit.

## Verification (2026-11-01)

| Check | Result |
| --- | --- |
| `cargo test` | all tests pass, including 11 TLS tests against a real local TLS server and a CONNECT proxy |
| `cargo clippy -D warnings` | clean |
| `cargo audit` | 0 vulnerabilities, 0 warnings (303 crates) |
| `systemd-analyze security` (GUI unit) | 1.5 OK |
| Live GUI check | no cookie 401, foreign Host 421, login link → HttpOnly SameSite=Strict cookie → 200 |

## Not yet verified

- The real TLS level of AFAS and Microsoft endpoints from your network (run `check-tls`).
- Whether ML-KEM in Schannel works through your firewall's TLS inspection.
- The exact Graph permissions the AFAS group integration requests.

## Reporting a vulnerability

Please do not open a public issue. Use the repository's private vulnerability reporting
(GitHub: *Security → Report a vulnerability*). Include the version, what you did, and what
happened. You will get a response within 7 days; fixes are released as a new version with
a note in the release notes.
