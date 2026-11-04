# Changelog

All notable changes. Versions follow [Semantic Versioning](https://semver.org/); before
1.0 a minor version may change configuration.

## 0.11.0 – 2026-11-03

Safer before the first real run, a test run you can actually read, and reports that
reach people. Existing configurations keep working; the state file is upgraded on the
next successful sync (version 2; an older program cannot read it back).

**Safety fixes**

- **A disable that slipped past the threshold:** an account that was active last run and
  is disabled now because its start date moved into the future (a rehire row, a
  correction, a wrong field) did not count towards `max_disables_per_run`. It does now.
- **An end date entered late:** an employee whose end date was more than
  `leaver_lookback_days` in the past (HR entered it late, or the timer was off for a
  month) was never sent as disabled and kept an enabled account. If the account was active
  last run, it is now sent once more, disabled. The same for a new employment that starts
  after the pre-hire window. Their groups (roles module) follow.
- **Missing from AFAS, reported once:** someone who disappeared from the GetConnector while
  active was reported in one run and then forgotten, with the account still enabled. They
  now stay in the state (`missing_since`) and are reported on every run until they are
  back in AFAS or marked as handled: `missing list`, `missing ack <number>` or the button
  on the GUI overview. Still never disabled automatically.
- **New thresholds:** `policy.max_new_per_run` (default 25) stops a run when many employee
  numbers are new since the last run (a changed employee number mapping or staff category
  prefix would create a second account for everybody); `policy.max_upn_changes_per_run`
  (default 5) stops a run when many sign-in names change. Proceed deliberately with
  `--allow-mass-create` / `--allow-upn-changes` or the boxes under Run in the GUI (typed
  confirmation is now `PROCEED ANYWAY` for every override). The first run is not limited
  by the new-records threshold.
- **Managers who left:** employees whose manager has left, is not in AFAS, is skipped
  because of a data error or starts later are grouped per manager in the report
  (`manager_gaps`), the terminal summary, the GUI and the notifications.

**Test run (dry-run) preview**

- Account by account what the run would do: create, create disabled, enable, disable,
  update (old → new per attribute), no change, link first, conflict, skipped, later, not
  sent, missing; where the account is (`example.com/Staff/Sales`, or Entra ID) and in which
  upload call it goes.
- With an app registration that may read users (`[preview]`, or that of an enabled module)
  a test run compares with Entra itself, and finds accounts that would be **created twice**
  (sign-in name exists without employee number). Without one it compares with what the last
  sync sent. `preview.new_accounts_ou` says where new accounts go.
- In the terminal the table fills up line by line; `afas-entra-sync preview` shows it again
  (`--all`, `--problems`, `--sync`, `--csv`, `--html`). The GUI has a **Preview** page with
  the pipeline from AFAS to Microsoft, a per-OU overview and a table that fills up call by
  call (CSS only, no JavaScript; still for people who prefer reduced motion), with HTML and
  CSV downloads. `sync --preview-html <file>` writes the same page. `preview --demo` shows
  it with fictional people.
- Values that were emptied in AFAS but stay in AD are shown as such.

**Notifications** (`[notify]`)

- Email (Microsoft Graph with its own app registration, `Mail.Send` scoped with Exchange
  RBAC for Applications), Microsoft Teams (Adaptive Card for Workflows or incoming
  webhooks), Slack (Block Kit) and any webhook (JSON, HMAC-SHA256 signed like the webhook
  module). Several channels, each with its own audience (`it`, `hr`) and triggers.
- Each message explains, per point: what happened, what it means, why the tool does not fix
  it itself, what to do and who does it. Points: run failed (per cause), safety stop (per
  threshold, with the people involved), manager who left, missing from AFAS, data errors
  with how to fix them, sign-in names that change, values emptied in AFAS that stay in AD
  (a leave date in particular), modules, certificates, provisioning failures and an upload
  Microsoft has not processed.
- The full log of the run goes along (attached to email, in the webhook, collapsed in
  Teams, the last lines in Slack for failures); it is also kept as `last-run.log`.
- A failure is sent once and repeated after `repeat_hours` (default 24); points of
  attention when something is new; "works again" and "all clear" once. Test runs only with
  `--notify`. A failing channel never changes the exit code.
- Personal data: employee numbers only by default; `personal_data = "names"` per channel
  adds names and sign-in names. Without names, quoted values in reasons and log lines are
  hidden too.
- `notify-test` sends an example to every channel; `notify-test --render <dir>` writes the
  examples to files without sending anything.

**Testing and monitoring**

- A test run writes `last-dry-run-report.json`; `last-report.json` is only written by a
  sync, so a manual test run can no longer hide a failed scheduled sync from monitoring.
- `check-logs` writes `last-check-logs.json`, warns (exit 3) when the last upload was not
  processed at all (paused or quarantined job, wrong job id), and notifies. The Checkmk
  check reports it as a second service.
- Departing employees: sessions are only revoked once the account is disabled in Entra
  (revoked earlier, the person could sign in again while the disable is on its way); an
  account still enabled two days after the end date is reported. `leaver.auto_reply_no_manager`
  is used when no manager is known, instead of "Please contact  ()".
- New hires: "already has a Temporary Access Pass" is noted once, not every hour.
- The modules read the Entra users once per run instead of once per module.
- `doctor` checks the preview look-up and the notification channels.
- `module-setup notify` and `module-setup preview` create their certificates.
- The GUI may no longer change `entra.job_id`, `entra.service_principal_id`,
  `policy.allowed_upn_domains`, `[notify]` or `[preview]`.

## 0.10.0 – 2026-11-01

Easier to set up, run and keep running. No configuration changes.

- **`doctor`**: one command that checks the whole chain and says, per line, what to do:
  configuration, token and key files (mode and owner), the state directory, AFAS (token,
  GetConnector, every mapped field, a sample of records), the Entra sign-in (with an
  explanation of common AADSTS codes), the permissions of the provisioning app and of each
  enabled module, certificate lifetimes, TLS, the systemd timer and the last run.
  Read-only: it uploads nothing, creates no sign-in codes and sends no mail. Exit 0 all
  good, 3 warnings, 61 something to fix. Also in the GUI: *Run → Run health check*.
- **`afas-fields`**: the fields the GetConnector returns, the kind of data in each and
  which setting uses it; settings that point to a missing field are listed with the fix.
  Shows no personal data.
- **`module-setup roles|joiner|leaver`**: creates the module's certificate and key (owned by
  the service user, key 0600), and prints the Entra steps, the exact permissions, the
  thumbprint and the config section to add. `--renew` for a new certificate.
- **No `-c` needed**: the configuration is found via `-c`, `AFAS_ENTRA_SYNC_CONFIG`,
  `/etc/afas-entra-sync/config.toml` or `./afas-entra-sync.toml`, in that order.
- **Wrong user caught**: `sync`, `serve`, `gui-enable` and `exception add|remove` refuse to
  run as root when the state directory belongs to the service user (root-owned files
  would break the next scheduled run), and show the right `sudo -u` command.
- **Readable output**: in a terminal, `sync` prints a summary (what changes, what needs
  attention, the next step) instead of JSON. `--json`, or output to a file, Ansible,
  Semaphore or systemd, gives the full report as before.
- **Certificate expiry warnings**: from 30 days before a certificate (provisioning app or
  a module) expires, the report and the GUI overview say so under `notices`; in the last 7
  days an otherwise good run ends with exit 3 so monitoring shows it.
- The GUI overview of a test run says how many records *would be* sent (it said "sent").
- Docs: the module setup used a wrong owner (`afas-entra-sync:` instead of the service user
  `afas-sync`) in its `chown` line; replaced by `module-setup`.

## 0.9.3 – 2026-11-01

Security assurance: self-assessed against **OWASP ASVS 5.0 Level 2** (all 253 Level 1 and 2
requirements, none unmet) and prepared for the **OpenSSF Best Practices** badge and
**Scorecard**. Evidence in `docs/security/`.

- **Fix (found by fuzzing):** an AFAS date with a non-ASCII character in its time part
  (e.g. `2024-01-01T00:00:0€`) crashed the whole run. It is now an ordinary data error
  for that one record.
- **GUI sign-in and sessions** (ASVS V3, V6, V7, V14, V16):
  - every sign-in gets its own random session; sessions end after 30 minutes without
    activity and after 8 hours; at most 20 at once;
  - the login link works once and expires after 15 minutes; a new one replaces it in
    `gui-login-url`;
  - cookie `__Host-afas_gui_session` with `Secure`, `HttpOnly`, `SameSite=Strict`;
  - "Sign out" on every page and "Sign out all sessions" on the GUI page, with
    `Clear-Site-Data`;
  - sign-in, refused sign-in, refused session, refused form token and sign-out are written
    to `audit.log`;
  - `Strict-Transport-Security` header; JSON downloads declare their charset.
- **No own cryptography:** the webhook HMAC now comes from AWS-LC (the library rustls
  already uses) instead of an own implementation.
- **No panics in production code:** `unwrap`, `expect` and `panic!` are denied by the
  compiler outside tests.
- The installer copies `/proc/self/exe`, the program that is actually running.
- Module certificates in the docs are valid for 365 days (was 730), in line with SECURITY.md.
- **Supply chain and CI:** `deny.toml` (RustSec, licences, crates.io only), CodeQL (Rust
  and Actions), OpenSSF Scorecard, secret scanning with a reviewed baseline, zizmor for
  workflows, shellcheck, a fuzz smoke test, Dependabot; every action pinned to a commit.
  Releases are built by GitHub Actions with a CycloneDX SBOM and signed build provenance
  (`gh attestation verify`).
- **Verifiable evidence:** raw scan output with checksums in `docs/security/evidence/`;
  the ASVS assessment is regenerated in CI from the official OWASP list (pinned to the
  `v5.0.0_release` tag by SHA-256) and the build fails when the CSV is out of date or any
  evidence points to a file, test or code symbol that does not exist.
- Fuzzing: `fuzz/` with four cargo-fuzz targets (AFAS response, configuration, small
  parsers, GUI request handler).

## 0.9.2 – 2026-11-01

Bug fixes from a review of the modules. No configuration changes are needed, but see the
two new configuration checks.

- **Graph:** a POST is no longer repeated after a network error or a 5xx, because Graph
  may already have carried it out (a second sign-in code or mail). 429 and 401 are still
  retried.
- **New hires (joiners):** an existing, usable Temporary Access Pass is never replaced
  (reported as a note); an expired or used one is removed first; when the outcome of
  creating one is unknown, any pass that appeared is removed; a manager who has left
  never receives the code (the fixed address is used instead); the start time is right
  on days the clocks change.
- **Access log:** a failure to write it is now a failure (exit 42), not silently ignored.
- **Departing employees (leavers):** the automatic reply is HTML-escaped and keeps its
  line breaks.
- **Configuration checks:** `roles.keep_leavers_days` must be smaller than
  `policy.leaver_lookback_days`, and the leaver module needs a lookback of at least 1;
  otherwise those actions would never happen.
- **Exceptions:** the CLI now checks that the group is in the role rules, like the GUI;
  both check the staff category prefix of the employee number.
- **Webhook:** a comparison older than 7 days counts as a new baseline, so switching the
  webhook on after a long pause does not send stale events.
- `joiner.sender` may not contain `/ ? # % \` (it is used in a URL path).
- Tests: the Graph client (retries, Retry-After cap, token refresh, paging, host check,
  network errors) and every decision rule of the modules at its boundaries. A mutation
  run on the module code went from 82 to 4 missed mutants, all equivalent
  (`MUTATION-REPORT.md`). The old test for unsafe groups passed for another reason and
  now checks the real refusal.

## 0.9.1 – 2026-11-01

- Plain language with the HR term in brackets everywhere: new hires (joiners), job changes
  (movers), departing employees (leavers), first sign-in code (Temporary Access Pass),
  conflicting groups (segregation of duties), staff category (population), skipped
  records (exclusions), test run (dry-run). Word list in README and guide.
- **Fix:** GUI settings pages showed keys left out of the config file as empty or off;
  saving a module page unchanged could switch off "sign out everywhere". The GUI now shows
  the value in use and treats a default as no change.

## 0.9.0 – 2026-11-01

Optional modules, each with its own app registration, maximum per run and test run:

- **Roles and licences:** group membership from HR data, licences through group-based
  licensing, conflicting groups (segregation of duties), time-limited exceptions.
- **New hires:** first sign-in code (Temporary Access Pass) mailed to the manager.
- **Departing employees:** sign out everywhere and an automatic reply.
- **Webhook:** signed (HMAC-SHA256) events for new hires, job changes and departing
  employees, with a send queue and retries.
- **Access log** with `report` (JSON/CSV) and GUI pages; `exception` command.
- Exit codes 21 (module stopped itself) and 42 (module failed).

## 0.8.0 – 2026-11-01

- One-step installer without Ansible: `install.sh` / `afas-entra-sync install`, `uninstall`.

## 0.7.0 – 2026-11-01

- TLS 1.3 only by default with post-quantum key exchange (X25519MLKEM768) preferred,
  `require` mode, `check-tls` command. Security review (`SECURITY.md`).
- Published under the Apache License 2.0.
