# afas-entra-sync

[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![OWASP ASVS 5.0 Level 2 (self-assessed)](https://img.shields.io/badge/OWASP%20ASVS%205.0-Level%202%20self--assessed-blue)](docs/security/README.md)

Fetches employees from an AFAS Profit GetConnector and delivers them to
**Microsoft Entra API-driven inbound provisioning** (`/bulkUpload`). The
Microsoft provisioning engine does the creating, updating and disabling in
AD (through the provisioning agent) or Entra ID. This program only does:
fetch → validate → decide active/inactive → check → upload.

> **Status:** tested against simulated AFAS and Microsoft endpoints that follow
> the documented behaviour. **Not** yet tested against a real AFAS environment
> or a real Entra tenant. See [Not yet verified](#not-yet-verified).

**Quick install** (Linux x86_64, no Ansible needed): download the release files
`afas-entra-sync-linux-x86_64`, its `.sha256` and `install.sh` into one directory, then

```
sudo ./install.sh
```

It verifies the checksum, creates the service user, directories, AFAS token, a validated
config, the Entra certificate and hardened systemd timers, and tells you what to upload to
Entra. Safe to run again; `sudo afas-entra-sync uninstall` removes it. Ansible users can use
[deploy/ansible](deploy/ansible/README.md) instead.

**Documentation:** step-by-step setup and operation in [docs/GUIDE.md](docs/GUIDE.md),
the optional modules in [docs/MODULES.md](docs/MODULES.md), changes in [CHANGELOG.md](CHANGELOG.md), security in [SECURITY.md](SECURITY.md)
and [docs/security](docs/security/README.md) (OWASP ASVS 5.0 Level 2 self-assessment, OpenSSF), Ansible deployment in
[deploy/ansible](deploy/ansible/README.md).

**Before the first real run:** a test run shows, account by account, what would happen and
where (create, enable, disable, update with old → new, accounts that would be created
twice), in the terminal, the GUI or as a page in your browser: see
[Test run preview](#test-run-preview). **While it runs:** failures and everything people
have to decide reach them by email, Teams, Slack or a webhook, explained in plain language
with the full log: see [Notifications](#notifications).

## Optional modules: new hires, job changes and departing employees

Each module is off until configured, signs in with its own app registration, plans first
(test run, also called dry-run) and stops by itself above its own maximum. Details: [docs/MODULES.md](docs/MODULES.md).

| Module | Does |
| --- | --- |
| Roles and licences | Group membership from HR data (department, job profile, ...); licences via group-based licensing; conflicting groups (segregation of duties); time-limited exceptions with a reason |
| New hires (joiners) | First sign-in code (Temporary Access Pass), valid from the start date, mailed to the manager; no passwords sent |
| Departing employees (leavers) | Sign out on every device and set an automatic reply after the end date |
| Webhook | Signed events for new hires, job changes and departing employees (joiner/mover/leaver) (HMAC-SHA256) for an ITSM tool or Power Automate, with retries |
| Access log | Who got or lost which access, when and through which module; JSON or CSV export |

## Screenshots

The optional admin GUI (off by default, local or behind your SSO proxy). Demo data.

| | |
| --- | --- |
| ![Overview of a run](docs/images/overview.png) | ![Modules](docs/images/modules.png) |
| ![New hires settings](docs/images/new-hires.png) | ![Access log](docs/images/access-log.png) |
| ![Health check](docs/images/health-check.png) | |

## Words used

Plain words first, with the usual HR or IT term in brackets:

| In this documentation | Also called | Meaning |
| --- | --- | --- |
| New hire | joiner | Someone who starts working here |
| New hire before the start date | pre-hire | Account exists already, still disabled |
| Job change | mover | Department, job title, manager or similar changes |
| Departing employee | leaver | Someone whose end date has passed |
| Returning employee | rehire | Someone who left and starts again with the same employee number |
| First sign-in code | Temporary Access Pass (TAP) | One-time code from Entra to sign in and set up MFA, instead of a password |
| Conflicting groups | segregation of duties (SoD) | Groups one person may never have together, e.g. paying and approving |
| Staff category | population | Contractors, externals or interns, each with their own config |
| Skipped records | exclusions | Records with a data error, not sent |
| Test run | dry-run | Shows what would happen; sends and changes nothing |
| Upload data | payload | The records exactly as Microsoft receives them |
| Send queue | outbox | Webhook messages waiting to be delivered |

## Design principle: when in doubt, send nothing

A record that is *not* sent is left alone by the provisioning engine. That is
always safer than sending a partial or wrong record. Therefore:

| Situation | Behaviour |
| --- | --- |
| Field missing in the AFAS response | Whole run stops (mapping error), exit 30 |
| Record with a data error (invalid UPN, date, field too long) | Only that record is skipped, exit 3 |
| Same employee number, different data | That employee is skipped, exit 3 |
| Same employee number, identical row | Merged, no problem |
| Same UPN for two employees | Both skipped, exit 3 |
| Manager is not in the upload | Record sent, manager not; warning; grouped per manager under `manager_gaps` |
| Active last run, now missing from AFAS | **Not** disabled; reported on every run (exit 3) until back in AFAS or marked handled (`missing ack`) |
| Active last run, end date now further back than `leaver_lookback_days` (entered late) | Sent once more, disabled |
| Active last run, start date moved into the future | Sent disabled; counts as a disable for the threshold |
| Too few records / large drop / many data errors | Nothing uploaded, exit 20 |
| More new disables than allowed | Nothing uploaded, exit 20 (to proceed deliberately: `--allow-mass-disable`) |
| Many employee numbers new since the last run (changed mapping or prefix) | Nothing uploaded, exit 20 (`--allow-mass-create`) |
| Many sign-in names (UPN) change at once | Nothing uploaded, exit 20 (`--allow-upn-changes`) |
| Upload fails halfway | Stop, old state stays; the next run sends everything again |
| Second run at the same time | Refused (lock file), exit 11 |

Every run sends the **full current set**. That makes it idempotent: a missed
or failed run is repaired by the next one.

## Active or not

- **Active** from the start date up to and including the end date (calendar date, `policy.timezone`).
- **New hire (pre-hire)**: from `prehire_days` before the start date, sent with `active: false` (account exists, disabled).
- **Departing employee (leaver)**: until `leaver_lookback_days` after the end date, sent with `active: false`. After that, no longer sent.
- Dates are taken literally. A date with a time other than midnight (e.g. `…T23:00:00Z`) is refused: a time zone was converted somewhere and the date cannot be trusted.

## Extra attributes (on/off)

In `[afas.fields.extra]` you switch each attribute on or off. A switched-off attribute is not
read (the AFAS field does not need to exist) and not sent.

| Toggle | SCIM field | Mapping in the provisioning app |
| --- | --- | --- |
| `phone_work` | `phoneNumbers[type eq "work"].value` | Available by default → `telephoneNumber` |
| `company` | enterprise `organization` | Available by default → `company` |
| `employee_type` | `userType` | Available by default → `employeeType` |
| `phone_mobile` | `urn:ietf:params:scim:schemas:extension:afas:1.0:User:mobilePhone` | Extend the schema, then → `mobile` |
| `office` | `…afas:1.0:User:officeLocation` | Extend the schema, then → `physicalDeliveryOfficeName` |
| `send_hire_date` | `…afas:1.0:User:hireDate` (YYYY-MM-DD) | Extend the schema, target attribute of your choice |
| `send_leave_date` | `…afas:1.0:User:leaveDate` (YYYY-MM-DD) | Extend the schema, target attribute of your choice |

Extending the schema: provisioning app → **Attribute mapping → Show advanced options → Edit
attribute list for API** → add the attribute with exactly the name from the table (including
the namespace). See Microsoft: *Extend API-driven provisioning to sync custom attributes*.

Validation: phone numbers only digits, spaces and `+ - ( ) .`, at least 6 digits, at most 64
characters; office at most 128, company and employee type at most 64. An invalid value excludes
only that record (exit 3), just like the other fields.

### Work address and job profile

| Toggle | SCIM field | Mapping |
| --- | --- | --- |
| `street`, `postal_code`, `city`, `country` | `addresses[type eq "work"]` (`streetAddress`, `postalCode`, `locality`, `country`) | Available by default → `streetAddress`, `postalCode`, `l`, `c` |
| `job_profile` | `…afas:1.0:User:jobProfile` | Extend the schema, then → e.g. `extensionAttribute2` |

`country` must be a 2-letter uppercase country code (NL). Only the address parts that are
present are sent.

**Job profiles to groups (roadmap option A).** Map `jobProfile` to an AD attribute that Entra
Connect Sync picks up (e.g. `extensionAttribute2`; these only exist if AD has the Exchange schema
extension). In Entra, create one dynamic group per profile, e.g.
`user.extensionAttribute2 -eq "FP-ICT-01"`. The tool needs no extra permissions for this.

## Staff categories (populations): contractors, externals, interns

Each population is its own config with its own GetConnector, its own `state.dir` and preferably
its own provisioning app (Microsoft advises one app per source). Example:

```toml
[population]
name = "contractors"         # shown in the report
id_prefix = "CTR-"           # externalId/employeeID becomes CTR-<number>
employee_type = "Contractor"
```

- The prefix prevents number 1001 of a contractor and number 1001 of an employee from matching
  the same AD account. Prefix + number together can be at most 16 characters.
- `employee_type` sets a fixed value; it cannot be combined with the `employee_type` toggle.
- Managers outside the population's own upload are not sent (as with employees); for contractors
  that gives a warning per record. Manager links across populations are on the roadmap.
- Run populations one after another (separate Semaphore templates or times); they share the
  Microsoft daily limit.

## Admin GUI (optional)

The GUI covers everything the tool can do: every setting (source, fields, extra attributes,
Entra, safety and windows, upload, population) and every action (dry-run, also for a date and
with payload download; run sync; check configuration; check provisioning logs).

### Turning it on and off

The GUI is **off** by default. The master switch is in the config file:

```toml
[gui]
enabled = true
```

- If it is `false` (or missing), `serve` does not start.
- If you turn it off while the GUI is running, the next request is refused and the server stops.
- In the GUI itself, the **GUI** page has a *Turn off GUI* button: it turns the GUI off and stops
  the server right away. The GUI can never turn itself on. To turn it back on, on the server:
  `afas-entra-sync gui-enable` (only works if the config file has `enabled = true`).

### Starting

```
afas-entra-sync serve                         # http://127.0.0.1:8080, local only
afas-entra-sync serve --read-only             # view only
afas-entra-sync serve --listen 0.0.0.0:8080 --trusted-proxy 10.0.0.5   # behind Traefik
```

### How changes are stored

Changes go to the GUI layer `<state.dir>/overrides.toml`, which is laid over the config file.
The config file (Ansible) is never touched; *Reset to config file* removes the GUI changes per
page. Every change is fully validated before it is saved, and applies from the next run.

Fixed in the config file and only visible in the GUI: the AFAS address and token source, tenant,
app registration, sign-in method, certificate and key paths, the login and Graph addresses, the
state directory and the GUI switch. That way nobody can use the GUI to send secrets or tokens to
another address. Clearing a value from the config file is only possible in that file.

### Running

- **Test run** (dry-run) runs in the background; the page shows the status and the result.
- **Run sync** asks for the word `APPLY`; proceeding past the disable threshold asks for
  `ALLOW DISABLE`. The safety thresholds always apply. A run at the same time as the scheduled
  sync is refused (shared lock file).

### Security

- Local only by default. In local mode you sign in with the link that `serve` writes to
  `<state.dir>/gui-login-url` (readable by the service user only, new on every start); it
  sets an HttpOnly, SameSite=Strict session cookie. Requests with another Host header are
  refused (DNS rebinding). Use an SSH tunnel to reach it from your workstation.
- Another address requires `--trusted-proxy`: then only connections from that IP, and the
  `X-authentik-username` header is required (Traefik forward auth with Authentik). That
  name goes into the audit log.
- Every form has a token (CSRF), POST at most 64 KB, all output escaped, no JavaScript, no
  external files, strict Content-Security-Policy.
- Audit log of every change, run and payload download in `<state.dir>/audit.log`.

## Building

```
cargo build --release          # Linux: target/release/afas-entra-sync
                               # Windows: target\release\afas-entra-sync.exe
```

Rust 1.89 or newer. No OpenSSL needed (rustls, uses the system certificate store).
Static Linux build: `cargo build --release --target x86_64-unknown-linux-musl`.

## Usage

```
afas-entra-sync doctor                               # check everything; says how to fix what is wrong
afas-entra-sync afas-fields                          # fields in the GetConnector and how they are mapped (no personal data)
afas-entra-sync sync                                 # test run (dry-run), sends nothing
afas-entra-sync sync --apply                         # actually upload
afas-entra-sync sync --as-of 2026-12-01              # test run as if it is that date
afas-entra-sync sync --dump-payload /tmp/p.json      # test run + inspect the upload data
afas-entra-sync sync --preview-html ~/preview.html   # test run + the account-by-account page for a browser
afas-entra-sync preview [--all|--problems] [--sync]  # what the last test run would do (or the last sync did)
afas-entra-sync preview --html f.html | --csv f.csv  # the same as a page or spreadsheet (personal data!)
afas-entra-sync preview --demo                       # the preview with fictional people, no config needed
afas-entra-sync missing list | missing ack <number>  # employees missing from AFAS while active; mark handled
afas-entra-sync notify-test [--channel NAME]         # send an example message to the [notify] channels
afas-entra-sync notify-test --render <dir>           # write example messages to files, send nothing
afas-entra-sync check-config                         # only check the configuration
afas-entra-sync check-logs --since-minutes 120       # check provisioning logs
afas-entra-sync check-tls                            # TLS version, cipher and key exchange per endpoint
afas-entra-sync serve                                # admin GUI (needs [gui] enabled = true)
afas-entra-sync gui-enable                           # turn the GUI back on after turning it off in the GUI
afas-entra-sync report [--employee N] [--since D] [--csv]   # access log of the modules
afas-entra-sync exception add|list|remove            # time-limited exceptions to the role rules
sudo afas-entra-sync install [--enable-sync] [flags] # install / upgrade on this host (see install --help)
sudo afas-entra-sync module-setup roles|joiner|leaver|notify|preview [--renew]   # certificate + Entra steps
sudo afas-entra-sync uninstall [--purge]             # remove (keeps config and state unless --purge)
```

**Which configuration.** No `-c` needed after `install`. The program uses the first of:
`-c <file>`, the environment variable `AFAS_ENTRA_SYNC_CONFIG`,
`/etc/afas-entra-sync/config.toml`, `./afas-entra-sync.toml`.

**Which user.** `sync`, `serve`, `gui-enable`, `check-logs`, `missing ack` and `exception add|remove` refuse to run as
root when the state directory belongs to the service user, because root-owned files
would break the next scheduled run. The message shows the right command
(`sudo -u afas-sync afas-entra-sync ...`). `doctor`, `afas-fields` and the other
read-only commands work as any user that can read the configuration.

**Output.** In a terminal, `sync` prints a short summary: what would change or changed,
what needs attention, and the next step. With `--json`, or when the output goes to a file,
Ansible, Semaphore or systemd, it prints the full report as JSON. The report is always
written to the state directory too: `last-report.json` by a sync, `last-dry-run-report.json`
by a test run (so a manual test run never hides a failed scheduled sync from monitoring).
It contains employee numbers and reasons, no names. Next to it: the log of the run
(`last-run.log`, `last-dry-run.log`) and the preview (`last-preview.json`,
`last-dry-run-preview.json`). Files are written with permissions 0600 (Linux). Note: the
previews, `--dump-payload` and `--preview-html` *do* contain personal data.

At a terminal only warnings and errors go to stderr (the summary is on stdout); under
systemd, Ansible or Semaphore the whole run is logged, line by line.

**Certificates.** Every run checks when the certificates of the provisioning app and of
the enabled modules expire. From 30 days before, the report (and the GUI overview) says
so under `notices`; in the last 7 days a run that was otherwise fine ends with exit 3, so
Semaphore or your monitoring shows it. Renew with `sudo afas-entra-sync install
--renew-cert` or `sudo afas-entra-sync module-setup <module> --renew`, then upload the new
certificate to the app registration.

**doctor.** Goes through the configuration, secret files, the state directory, AFAS (token,
GetConnector, every mapped field), the Entra sign-in (with an explanation of the AADSTS
code when it fails), the permissions of the provisioning app and of each enabled module,
certificate lifetimes, TLS, the systemd timer and the last run. Each line is ok, a
warning or a problem, with what to do about it. It changes nothing: it signs in and reads,
but uploads nothing, creates no sign-in codes and sends no mail. Permissions that can only
be tested by acting (upload, `Mail.Send`, sign out everywhere) are listed as not verified.
Also in the GUI under *Run → Run health check*.

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | All OK |
| 2 | Invalid command line (unknown option or argument) |
| 3 | Completed, but something needs attention: skipped or missing records, or a certificate that expires within 7 days; `check-logs`: the last upload was not processed |
| 10 | Configuration error |
| 11 | Another run is active |
| 20 | Safety stop: **nothing** uploaded |
| 21 | A module stopped itself above its maximum; that module changed nothing |
| 30 | AFAS error, or the AFAS response does not match the configuration |
| 40 | Getting a token from Entra failed |
| 41 | Upload failed (possibly partially uploaded; the next run repairs it) |
| 42 | A module failed (sign-in, Graph or webhook); see `modules` in the report |
| 50 | `check-logs`: provisioning logs contain failures |
| 60 | `check-tls`: an endpoint does not meet the `[tls]` policy |
| 61 | `doctor`: at least one check failed (warnings only give 3) |

In Semaphore anything other than 0 is a failed task. That is deliberate:
someone should see exit 3.

## Test run preview

A test run (`sync` without `--apply`) works out, per employee, what Microsoft would do:

| Action | Meaning |
| --- | --- |
| Create / Create, disabled | A new account; disabled until the start date for a new hire |
| Enable / Disable | Start date reached / end date passed (with the reason) |
| Update | Which values change, old → new, with the AD attribute |
| No change | Up to date. A value emptied in AFAS that stays in AD is still shown |
| Link first | An account with this sign-in name exists without employee number: Microsoft would create a second one. Set `employeeID` first (guide, step 5d) |
| Conflict | The sign-in name belongs to another employee number |
| Skipped / Later / Not sent / Missing in AFAS | Not in the upload, and why |

Each account also shows **where** it is (`example.com/Staff/Sales`, from AD through Entra;
new accounts go to `preview.new_accounts_ou`) and in which upload call it goes.

What it compares with: Entra ID as it is now, when an app registration that may read users
is available (`[preview]`, or that of an enabled module; read-only, `User.Read.All`);
otherwise what the last successful sync sent; on the very first run without a look-up,
nothing (every account is "new for this tool"). Attributes that Entra does not show (cost
center, for example) are not compared, and the preview says so. The look-up never makes a
run fail.

Where to see it: at a terminal right after the test run (the table fills up line by line),
again with `afas-entra-sync preview`, in the GUI under **Preview** (with the flow from AFAS
to Microsoft, accounts per OU, and a table that fills up call by call; downloads as page or
CSV), or as a page you open in a browser (`sync --preview-html`, `preview --html`). A sync
writes the same overview of what it sent (`preview --sync`, GUI: Last sync).

## Notifications

`[notify]` sends what people have to know after a sync or `check-logs`, to any number of
channels: email (through Microsoft Graph, own app registration, `Mail.Send` scoped to one
mailbox), Microsoft Teams (Workflows or incoming webhook), Slack (incoming webhook) or any
HTTPS endpoint (signed JSON). Each point says what happened, what it means, why the tool does
not fix it itself, what to do and who does it (IT or HR); the full log of the run goes along.

| Point | For |
| --- | --- |
| The sync did not run (configuration, AFAS, sign-in, upload, unexpected), with what to check | IT |
| Safety stop, per threshold, with the people involved and how to proceed deliberately | IT (and HR) |
| A manager who left, is not in AFAS or is skipped, while employees still report to them | HR |
| Employees missing from AFAS while their account stays enabled | HR and IT |
| Data errors in AFAS, each with how to fix it | HR |
| Sign-in names that change; values emptied in AFAS that stay in AD (a leave date in particular) | IT |
| Modules that failed or stopped; certificates that expire | IT |
| Provisioning failures Microsoft reports, with the likely cause; an upload that was never processed | IT |

A failure is sent once and again after `repeat_hours` (24 by default) while it lasts; points
of attention when something is new (marked NEW), and repeated while open; "the sync works
again" and "all clear" once. Each channel can take only some points (`audience = ["hr"]`)
or triggers (`on`). Employee numbers only by default; `personal_data = "names"` adds names
and sign-in names. `notify-test` sends an example, `notify-test --render <dir>` writes the
examples to files. Setup: [docs/MODULES.md](docs/MODULES.md#notifications).

## Configuration

See `afas-entra-sync.example.toml`. Unknown keys are rejected.
Secrets are never in the file: the AFAS token via `token_env` or `token_file`,
Entra via a certificate (recommended) or `client_secret_env`. The token file and the
private key must be mode 0600 and owned by the service user (or root); otherwise the run
stops with a configuration error.

### TLS

All outgoing connections use TLS 1.3 by default, with post-quantum hybrid key exchange
(X25519MLKEM768) offered first and classical X25519 as fallback. `[tls] post_quantum =
"require"` refuses servers without ML-KEM. `check-tls` shows what each endpoint really
negotiates. Details: `SECURITY.md`.

### Number of API calls

With Entra ID P1, Microsoft allows **2,000 calls per 24 hours**, with at most
50 records per call.

Example with 600 employees and a run every hour:

- calls per run: 600 ÷ 50 = **12**
- calls per day: 12 × 24 = **288**
- headroom: 2,000 − 288 = 1,712 calls left

`max_calls_per_run` stops the run if more calls are needed than you expect.

## Setup on the Microsoft side

1. Enterprise app **API-driven provisioning to on-premises Active Directory** (or to Entra ID for cloud-only). Provisioning agent on Windows Server 2025 or 2022 (Microsoft's recommendation); keep TLS 1.2 enabled there. See `SECURITY.md`.
2. App registration with a certificate; application permissions `SynchronizationData-User.Upload` and `ProvisioningLog.Read.All`, admin consent.
3. In the provisioning app:
   - **Matching**: `externalId` ↔ `employeeID` (default).
   - **UPN**: `userName` → `userPrincipalName`, apply on create and update, without `SelectUniqueValue`. The UPN comes from AFAS; the AFAS group sync matches on it.
   - **Target object actions**: turn *Delete* off.
   - **Prevent accidental deletions** on, with a low threshold. Disables count too.
   - Fill in the **Notification email** (otherwise the job goes into quarantine).
   - Pilot: scoping filter on one department.
4. `service_principal_id` and `job_id` are in the endpoint URL under *Provisioning → View technical information*.

## Behaviour you need to know

- **Empty optional fields are omitted**, not sent as `null`. If *clear attribute values (preview)* is on in the mapping, Microsoft clears an attribute that is missing. An empty department in AFAS then empties the department in AD. That is usually what you want, but be aware of it.
- **An employee who disappears from the GetConnector** (filtered, deleted) is not disabled automatically. They show up in `disappeared_while_active` and `missing` (with since when) on every run, which ends with exit 3, until they are back in AFAS or marked as handled with `missing ack <number>` (or in the GUI).
- **Emptied values stay in AD**, unless *clear attribute values* is on. When a leave date is removed (contract extended) and Lifecycle Workflows use it, clear it by hand; the notification and the preview point it out.
- **Multiple employments**: the GetConnector must return one row per employee. Two different rows for one employee number are skipped.
- **A departing employee (leaver) without an existing account** within the lookback period is created by Microsoft as a disabled account. So keep `leaver_lookback_days` short.
- **First run**: without state, every departing employee in the window counts as a possible disable. With a large first load the threshold applies; proceed deliberately with `--allow-mass-disable`.
- `--as-of` only works in a test run (dry-run).

## Tests

```
cargo test                       # all tests
PROPTEST_CASES=20000 cargo test --release --test props   # extra heavy property tests
```

- **unit**: dates, text, UPN rules, row validation, windows (exact limits), duplicates, managers, all safety thresholds (exact limits), SCIM shape against the Microsoft example, config errors, state, Retry-After, JWT (verified with the public key, thumbprints compared with OpenSSL).
- **e2e**: full runs against mock AFAS and mock Entra: paging, pacing, 429 + Retry-After, *bucket full*, 5xx backoff, 401 + token refresh, 400 halfway, giving up after max attempts, all thresholds, broken AFAS responses, lock, broken state, provisioning logs including refusing a `nextLink` to another host.
- **extra**: attribute toggles, work address, job profile, populations.
- **web**: the admin GUI without networking: master switch, local sign-in and Host check, proxy/Authentik, CSRF, read-only, every page, locked fields, settings round trip and reset, runs and confirmations.
- **tls**: TLS policy against a real local TLS server: post-quantum negotiation, fallback, `require` refusing classical servers, TLS 1.2 refused by default, untrusted certificate and wrong host name refused, CONNECT proxy, and the HTTP client enforcing the same policy.
- **cli**: the real program with environment variables and a client secret; checks that the secret appears nowhere in the output.
- **props**: thousands of random AFAS datasets with garbage and duplicates; invariants (no duplicate IDs or UPNs sent, excluded never also sent, every record exactly once in the payloads, at most 50 per call).
- **mutation tests** (`cargo mutants`): the code was deliberately broken in ~330 places; every real fault is caught by a test. Details and the 10 accepted (equivalent or cosmetic) cases: `MUTATION-REPORT.md`.

## Not yet verified

These points are based on documentation and can only be confirmed in your own
environment. Do that in a pilot with a scoping filter.

1. Field names and date format of your GetConnector.
2. The `orderbyfieldids` parameter (used as in the Tools4ever AFAS connector; not found on the official AFAS page).
3. The real behaviour of the provisioning engine with your mapping (matching, UPN, manager, clear attribute values).
4. The `$filter` on `jobId` in `check-logs`.
5. The preview's user look-up with `$expand=manager` (paged by 100), and which attributes Connect Sync really carries to Entra in your tenant.
6. Delivery to your Teams Workflows URL, Slack app and mail tenant (`notify-test`).
7. Certificate authentication against real Entra ID (the JWT is verified cryptographically).
8. The TLS level the endpoints really negotiate from your network (`check-tls`).

## License

Copyright 2026 The afas-entra-sync Authors. Licensed under the
[Apache License, Version 2.0](LICENSE). See [NOTICE](NOTICE); third-party licenses of the
components in the binary are in [THIRD-PARTY-LICENSES.txt](THIRD-PARTY-LICENSES.txt).
Contributions are welcome, see [CONTRIBUTING.md](CONTRIBUTING.md).

AFAS and AFAS Profit are trademarks of AFAS Software B.V. Microsoft, Entra and Active
Directory are trademarks of Microsoft Corporation. This project is not affiliated with,
endorsed by or supported by AFAS Software or Microsoft. Provided "as is", without
warranty: test it in your own environment before relying on it.
