# afas-entra-sync guide

How to set up, run and operate afas-entra-sync: from AFAS to Microsoft Entra ID or
on-premises Active Directory, including existing accounts, groups and day-to-day operation.
For the design rules see the [README](../README.md); for security see
[SECURITY.md](../SECURITY.md).

## How it works

The tool handles user accounts only. Groups are handled by AFAS itself through its built-in
Entra ID integration. Two processes, each with one job, linked by the same UPN.

What the tool does: every hour it fetches all employees from AFAS, validates them, decides
per employee whether the account must be active, and sends the whole list to Microsoft.
Microsoft compares that with what exists and creates, updates or disables accounts.

What the tool does not do:

- Delete accounts. It only disables.
- Assign groups or licences. The AFAS integration does that, or you use groups in Entra.
- Set or send passwords.
- Touch anything that does not come from AFAS: admin accounts, service accounts and
  accounts of people outside the GetConnector stay as they are.

### Hybrid environments (AD + Entra Connect Sync)

If you already have on-premises AD synchronised to Entra with Entra Connect Sync, the tool
only adds a provisioning app and an agent. Accounts are created in AD from AFAS, and
Connect Sync carries them to Entra as always.

| Part | Before | After |
| --- | --- | --- |
| Create account | Manually by IT after an HR request | Automatically from AFAS, before the start date, disabled |
| Enable account | Manually | Automatically on the start date |
| Job title, department, manager | Manually or not at all | From AFAS, updated every hour |
| Disable on leaving | Manually | Automatically the day after the end date |
| Groups and licences | Manually in Entra | HR in AFAS, through the AFAS integration |
| Entra Connect Sync | Runs | Keeps running unchanged |

Lead time of a change: up to 60 minutes until the next run, plus processing by Microsoft,
plus up to 30 minutes of Connect Sync. Count on about 90 minutes until it shows in Entra;
that is why new accounts are created days in advance.

## What you need

Arrange these before you start; most need an owner other than IT.

- **Licence:** Entra ID P1 or higher. Entra ID Governance raises the daily API limit to
  6,000 calls and adds Lifecycle Workflows (for example an automatic Temporary Access Pass).
- **Entra roles:** Application Administrator, plus Hybrid Identity Administrator for AD.
- **AFAS:** someone with admin rights in Profit to create a GetConnector and an app connector.
- **HR agreement:** start date, end date, UPN and manager are always filled in; AFAS is the
  source of truth.
- **Windows Server 2025 or 2022** (Microsoft's recommendation; no Server Core),
  domain-joined, 4 GB RAM, .NET 4.7.1+, TLS 1.2 enabled. The Microsoft provisioning agent
  runs here. Treat it as Tier 0. It may be the Entra Connect Sync server.
- **Domain Admin once**, for the agent's gMSA.
- **A Linux host** for the tool, with outbound HTTPS to AFAS (`*.rest.afas.online`) and
  Microsoft (`login.microsoftonline.com`, `graph.microsoft.com`).
- **AD Recycle Bin** enabled.
- **A target OU** in AD for new accounts, inside the Connect Sync scope.
- **Existing accounts:** `employeeID` filled with the AFAS employee number. Without it,
  Microsoft creates duplicate accounts (see [Existing accounts](#step-5--existing-accounts-and-dry-run)).

## Step 0 – Prepare AD (hybrid only)

Checks in the existing environment; none of them changes anything for current users. Run the
PowerShell on a management server with RSAT.

**0a. UPN suffix known in AD.** The provisioning app creates accounts with the UPN from AFAS.
If AD does not know the suffix, creation fails.

```powershell
(Get-ADForest).UPNSuffixes          # must contain your UPN domain
# if not, add it (Enterprise Admin):
# Set-ADForest -Identity (Get-ADForest) -UPNSuffixes @{Add='example.com'}
```

**0b. Target OU inside the Connect Sync scope.** Create the OU if needed. In the Entra
Connect wizard (Configure → Customize synchronization options → Domain and OU filtering),
check that it is included. Otherwise new accounts never reach Entra.

**0c. AD Recycle Bin on.** A safety net in case something is ever deleted.

```powershell
Get-ADOptionalFeature 'Recycle Bin Feature' | Select-Object Name, EnabledScopes
# empty = off. Enabling cannot be undone:
# Enable-ADOptionalFeature 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target (Get-ADForest).Name
```

**0d. Index employeeID.** Microsoft looks accounts up on this attribute on every run; without
an index that gets slow as AD grows. This is a schema change (Schema Admin): follow
Microsoft's guidance and do it in a maintenance window.

**0e. Who writes employeeID today?** Make sure no other process (script, other HR system)
fills it. From now on it belongs to AFAS.

```powershell
Get-ADUser -Filter 'employeeID -like "*"' -Properties employeeID |
  Measure-Object | Select-Object Count
```

A count above 0 is fine, but know where the values come from: in step 5 they must equal the
AFAS employee number.

## Step 1 – Prepare AFAS

Create one GetConnector with the employee data, and an app connector with a token that may
only read that GetConnector.

**1a. GetConnector.** Requirement: one row per employee. Two rows with the same employee
number and different data (for example two employments) are skipped. Name the fields as in
this table, or adjust `[afas.fields]` in the config later.

| GetConnector field | Content | Required |
| --- | --- | --- |
| Personeelsnummer | Unique employee number, at most 16 characters | Yes |
| Roepnaam | Given name | Yes |
| Voorvoegsel | Name prefix, e.g. "van der" | No |
| Achternaam | Family name without prefix | Yes |
| UPN | UPN of the linked Profit user, e.g. j.jansen@example.com | Yes |
| EmailWerk | Work email | No |
| Functie | Job title | No |
| Afdeling | Department | No |
| PersoneelsnummerLeidinggevende | Employee number of the manager | No |
| Kostenplaats | Cost center | No |
| DatumInDienst | Start date | Yes |
| DatumUitDienst | End date, empty while employed | Yes (may be empty) |

Optional extra attributes (phone, mobile, office, company, employee type, job profile, work
address) each have an on/off toggle in `[afas.fields.extra]`; see the README.

Filter the GetConnector if needed, for example own staff only. Anything not in the
GetConnector is never touched.

**1b. App connector and token.** In Profit, create an app connector for the REST service, add
only this GetConnector, and generate a token for a separate user. Store the token in a vault.

**1c. Test** from the Linux host, with the token's data value in `AFAS_TOKEN`:

```bash
AUTH="AfasToken $(printf '<token><version>1</version><data>%s</data></token>' "$AFAS_TOKEN" | base64 -w0)"
curl -s -H "Authorization: $AUTH" \
  "https://12345.rest.afas.online/ProfitRestServices/connectors/Entra_Medewerkers?skip=0&take=3&orderbyfieldids=Personeelsnummer"
```

You get JSON with a `rows` list. Check the date format: `2024-01-31T00:00:00Z` or
`2024-01-31`. The tool refuses a time other than midnight.

## Step 2 – Entra: the provisioning app

A ready-made Microsoft app that receives the tool's data and manages the accounts.

**2a. Create the app.**

1. Entra admin center → Entra ID → Enterprise apps → New application.
2. Search for *API-driven* and choose **API-driven provisioning to on-premises Active
   Directory**. Cloud-only accounts without AD? Choose *… to Microsoft Entra ID*.
3. Name it, for example `AFAS-Employees-to-AD`, then Create.
4. Provisioning → Get started, Provisioning Mode Automatic, Save.

**2b. Install the provisioning agent (AD only).**

1. Click the provisioning agent banner → Accept terms & download.
2. Install the agent on the Windows Server from the checklist. The wizard creates a gMSA and
   asks for Domain Admin once.
3. Do **not** create a Cloud Sync configuration in the wizard. The agent is only used by the
   provisioning app; Connect Sync stays the only AD → Entra sync. Two syncs on the same
   users cause conflicts.
4. Back in the app: choose your domain, enter the DN of the target OU, Test connection, Save.

**2c. Settings.**

| Setting | Value |
| --- | --- |
| Notification email | A team mailbox. Empty means the job goes into quarantine right away. |
| Prevent accidental deletions | On, threshold e.g. 10. Disables count too. |
| Scope | For the pilot a scoping filter, e.g. `department EQUALS ICT` |

**2d. Mappings.**

| Check | Why |
| --- | --- |
| Matching: `externalId` → `employeeID`, precedence 1, no second matching attribute | One unambiguous key |
| `userName` → `userPrincipalName`, direct, no `SelectUniqueValue` or `RandomString` | The UPN comes from AFAS; the group integration matches on it |
| `sAMAccountName` has a mapping (max 20 characters, unique) | Required in AD; check the default against your naming convention |
| `mail` mapped to `emails[type eq "work"].value` | Only if you use mail in AD |
| Manager, department, title mapped; cost center only to a free attribute (e.g. an extensionAttribute) | Org chart and dynamic groups |
| Target object actions: Delete off | The tool never deletes; Microsoft should not either |

**2e. Start and note the IDs.** Start provisioning; the job now waits for data. Under
Statistics to date → View technical information, copy the Provisioning API Endpoint:
`https://graph.microsoft.com/beta/servicePrincipals/<service_principal_id>/synchronization/jobs/<job_id>/bulkUpload`.
You need both values for the config.

## Step 3 – Entra: sign-in for the tool

The tool signs in as its own app registration with a certificate. It is the only identity
that may upload data.

**3a. Create the certificate** on the Linux host, as the service user, after the tool is
installed (step 4), so the key is owned by that user:

```bash
sudo -u afas-sync openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 365 \
  -subj "/CN=afas-entra-sync" \
  -keyout /etc/afas-entra-sync/key.pem -out /etc/afas-entra-sync/cert.pem
sudo chmod 600 /etc/afas-entra-sync/key.pem
```

`key.pem` never leaves this machine; the tool refuses it if group or others can read it.
Put the expiry date in the team calendar with a month's margin.

**3b. App registration.**

1. Entra ID → App registrations → New registration, name `afas-entra-sync`, Register.
2. Note the Application (client) ID and Directory (tenant) ID.
3. Certificates & secrets → Certificates → Upload certificate → `cert.pem`.
4. API permissions → Microsoft Graph → Application permissions:
   `SynchronizationData-User.Upload` (upload) and `ProvisioningLog.Read.All` (`check-logs`).
5. Grant admin consent. Remove the default delegated `User.Read`; the tool does not use it.

This app has no rights on users or groups themselves: it can only hand data to the
provisioning job. A client secret is possible (`auth = "client_secret"`), but use a
certificate in production.

## Step 4 – Install the tool

One static file without dependencies. It does not have to run on the agent server; any Linux
host (x86_64) with HTTPS to AFAS and Microsoft will do.

**With the installer (recommended without Ansible).** Put the release files
`afas-entra-sync-linux-x86_64`, `afas-entra-sync-linux-x86_64.sha256` and `install.sh` in one
directory and run:

```bash
sudo ./install.sh
```

It asks for the AFAS environment number, GetConnector, tenant ID, client ID, service
principal ID, job ID, UPN domain(s), number of employees and the AFAS token (hidden), and
validates every answer before it writes anything. Then it:

- verifies the binary's SHA-256 and installs it as `/usr/local/bin/afas-entra-sync`;
- creates the system user `afas-sync` and `/etc/afas-entra-sync` and `/var/lib/afas-entra-sync` (0700);
- writes the AFAS token (0600) and a validated `config.toml` (0600) from the example config;
- creates `cert.pem` and `key.pem` (RSA 3072, SHA-256, valid 365 days, key 0600) and prints
  the thumbprint Entra will show after you upload `cert.pem` in step 3b;
- writes hardened systemd units for the hourly sync (:07) and check-logs (:22), not yet enabled.

Unattended, with every value as a flag and the token from a file (delete it afterwards):

```bash
sudo ./install.sh --token-file token.txt --afas-env 12345 \
  --tenant-id <tenant> --client-id <client> --service-principal-id <sp> --job-id <job> \
  --upn-domain example.com --employee-count 600
```

Running it again keeps the config, token and certificate and only updates the binary and
units, so it is also the upgrade path. `--reconfigure`, `--replace-token` and `--renew-cert`
replace those (the old files are kept as backups). After the pilot dry-run, go live with
`sudo afas-entra-sync install --enable-sync`. Remove with `sudo afas-entra-sync uninstall`
(add `--purge` to also delete config, token, key, state and the user).

When you use the installer, it already creates the certificate: skip the openssl command in
step 3a and upload `/etc/afas-entra-sync/cert.pem`.

**With Ansible:** see [deploy/ansible](../deploy/ansible/README.md). It creates the user and
directories, verifies the binary's checksum, places a validated config and sets the key
permissions.

**By hand (as root):**

```bash
useradd --system --no-create-home --shell /usr/sbin/nologin afas-sync
install -m 755 afas-entra-sync-linux-x86_64 /usr/local/bin/afas-entra-sync
install -d -m 700 -o afas-sync -g afas-sync /etc/afas-entra-sync /var/lib/afas-entra-sync
# AFAS token (only the data value, or the whole <token> XML)
printf '%s' 'PASTE_TOKEN_HERE' > /etc/afas-entra-sync/afas.token
chown afas-sync: /etc/afas-entra-sync/afas.token && chmod 600 /etc/afas-entra-sync/afas.token
afas-entra-sync --version
```

Build it yourself: `cargo build --release --target x86_64-unknown-linux-musl` (Rust 1.89+).

**Config.** Copy `afas-entra-sync.example.toml` to `/etc/afas-entra-sync/config.toml` and set:

| Section | Key | Value |
| --- | --- | --- |
| `[afas]` | `base_url` | `https://<environment>.rest.afas.online/ProfitRestServices` |
| `[afas]` | `connector` | Your GetConnector |
| `[afas]` | `token_file` | `/etc/afas-entra-sync/afas.token` (remove `token_env`) |
| `[afas.fields]` | all fields | Field names from your GetConnector |
| `[entra]` | `tenant_id`, `client_id` | From step 3 |
| `[entra]` | `certificate_pem`, `private_key_pem` | `/etc/afas-entra-sync/cert.pem` and `key.pem` |
| `[entra]` | `service_principal_id`, `job_id` | From step 2e |
| `[policy]` | `allowed_upn_domains` | e.g. `["example.com"]` |
| `[policy]` | `min_records` | A bit below your current number of employees in scope |
| `[state]` | `dir` | `/var/lib/afas-entra-sync` |
| `[tls]` | `min_version`, `post_quantum` | Keep the defaults (`"1.3"`, `"prefer"`) |

Start strict with the safety thresholds in `[policy]`; you can always relax them.

**Check:**

```bash
sudo -u afas-sync afas-entra-sync -c /etc/afas-entra-sync/config.toml check-config
sudo -u afas-sync afas-entra-sync -c /etc/afas-entra-sync/config.toml check-tls
```

A typo or unknown key gives a clear error (exit 10), never a silent default. `check-tls`
shows the TLS version, cipher and key exchange per endpoint (exit 60 if one fails the policy).

## Step 5 – Existing accounts and dry-run

Without `--apply` nothing is sent to Microsoft, so this is safe to try.

**5a. Dry-run.**

```bash
sudo -u afas-sync afas-entra-sync -c /etc/afas-entra-sync/config.toml \
  sync --dump-payload /var/lib/afas-entra-sync/payload.json
```

The report (JSON on screen and in `/var/lib/afas-entra-sync/last-report.json`) shows:

- `counts`: active, new (still disabled), leavers.
- `exclusions`: records with data errors and why. Have HR fix them before going live.
- `warnings`: for example a manager who is not in the upload.
- `violations`: a safety threshold was hit.

**5b. Link existing accounts.** Microsoft recognises existing AD accounts only by
`employeeID`. If it is empty, a second account is created. Extract employee number and UPN
from the payload, then delete the payload (it contains personal data):

```bash
sudo jq -r '.[].Operations[].data | [.externalId, .userName] | @csv' \
  /var/lib/afas-entra-sync/payload.json > /tmp/link.csv
sudo rm /var/lib/afas-entra-sync/payload.json
```

**5c. Compare (read only).** On a management server with RSAT. This script changes nothing:

```powershell
$rows = Import-Csv link.csv -Header EmployeeNumber,UPN
$report = foreach ($r in $rows) {
  $upn = $r.UPN -replace "'", "''"
  $nr  = $r.EmployeeNumber -replace "'", "''"
  $u = Get-ADUser -Filter "UserPrincipalName -eq '$upn'" -Properties EmployeeID
  # is this employee number already on another account?
  $elsewhere = @(Get-ADUser -Filter "employeeID -eq '$nr'" |
                 Where-Object { -not $u -or $_.SID -ne $u.SID })
  $status = if ($elsewhere.Count -gt 0) { 'NUMBER_ELSEWHERE' }
            elseif (-not $u) { 'NO_ACCOUNT' }
            elseif (-not $u.EmployeeID) { 'LINK' }
            elseif ($u.EmployeeID -eq $r.EmployeeNumber) { 'OK' }
            else { 'CONFLICT' }
  [pscustomobject]@{ EmployeeNumber = $r.EmployeeNumber; UPN = $r.UPN; Status = $status
                     CurrentEmployeeID = $u.EmployeeID
                     OtherAccount = ($elsewhere.UserPrincipalName -join ';') }
}
$report | Group-Object Status | Select-Object Name, Count
$report | Export-Csv link-report.csv -NoTypeInformation -Encoding UTF8
```

| Status | Meaning | Action |
| --- | --- | --- |
| OK | Already linked | Nothing |
| LINK | Account exists, employeeID empty | Step 5d |
| CONFLICT | Account has a different employeeID | Find out which is right; never automatically |
| NO_ACCOUNT | No AD account with this UPN | UPN in AFAS differs from AD (fix in AFAS), or a genuinely new employee (Microsoft creates the account) |
| NUMBER_ELSEWHERE | The employee number is already on another account | Fix first; two accounts with one number make linking unreliable |

**5d. Link.** Only when CONFLICT and NO_ACCOUNT are explained. First with `-WhatIf`, then
without:

```powershell
Import-Csv link-report.csv | Where-Object Status -eq 'LINK' | ForEach-Object {
  $upn = $_.UPN -replace "'", "''"
  Get-ADUser -Filter "UserPrincipalName -eq '$upn'" |
    Set-ADUser -EmployeeID $_.EmployeeNumber -WhatIf
}
```

Run 5c again: everything must be OK, apart from explained NO_ACCOUNTs. Delete the CSV files.

**5e. Look ahead (optional).** `sync --as-of 2026-12-01` shows what the tool would do on that
date. Useful to check leavers and new employees.

## Step 6 – Pilot and go-live

The tool always sends all employees; the scoping filter in the provisioning app decides who
Microsoft actually processes. That lets you expand per department.

**6a. First real run** with the scoping filter on the pilot department:

```bash
sudo -u afas-sync afas-entra-sync -c /etc/afas-entra-sync/config.toml sync --apply
```

After 5 to 10 minutes the result is in Enterprise app → Provisioning logs, or via
`check-logs`.

**6b. Test cases.** Tick off what you have seen yourself:

- Existing employee: only attributes updated, no new account.
- Manager in AD is right (Organization tab in ADUC).
- A change in AFAS (e.g. job title) is in AD and Entra within about 90 minutes.
- New employee (start within the pre-hire window): disabled account in the target OU, in
  Entra within 30 minutes.
- That same new employee in an AFAS group: one account in Entra, no cloud-only duplicate
  (see [Groups](#groups)).
- Start date reached: account enabled.
- Leaver: disabled the day after the end date and removed from the AFAS groups.
- Admin and service accounts unchanged.

**6c. Schedule** (step 7) and let the pilot run for 2 to 4 weeks.

**6d. Expand.** Run a dry-run and 5c again for the new departments, then widen or remove the
scoping filter. The first run without earlier state counts every leaver in the window as a
possible disable; if that hits the threshold, check the list and proceed deliberately with
`--allow-mass-disable`.

**6e. Change the process** with HR and the service desk:

| Agreement | Who |
| --- | --- |
| Account requests by email stop; HR records joiners, movers and leavers only in AFAS | HR |
| The UPN is generated in AFAS, no longer by IT | HR, IT |
| First password or Temporary Access Pass on day 1 | Service desk |
| Exit 3: excluded records go to HR | IT |
| Group membership changes go through AFAS, not Entra | HR, IT |

## Step 7 – Schedule and monitor

Run `sync --apply` every hour and alert on any exit code other than 0. Use one scheduler:
the tool refuses a second run at the same time (exit 11).

**Installer:** `sudo afas-entra-sync install --enable-sync` enables the sync and check-logs
timers it wrote in step 4; nothing else to do.

**Option A: systemd timer by hand.** `/etc/systemd/system/afas-entra-sync.service`:

```ini
[Unit]
Description=AFAS to Entra provisioning
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
User=afas-sync
ExecStart=/usr/local/bin/afas-entra-sync -c /etc/afas-entra-sync/config.toml sync --apply
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ReadWritePaths=/var/lib/afas-entra-sync
CapabilityBoundingSet=
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
SystemCallFilter=@system-service
```

`/etc/systemd/system/afas-entra-sync.timer`:

```ini
[Unit]
Description=AFAS to Entra provisioning, hourly

[Timer]
OnCalendar=*-*-* *:07:00
Persistent=true

[Install]
WantedBy=timers.target
```

```bash
systemctl daemon-reload && systemctl enable --now afas-entra-sync.timer
journalctl -u afas-entra-sync -n 50     # last run
```

**Option B: Ansible from a scheduler** (Semaphore, AWX, cron): schedule
`deploy/ansible/run-afas-entra-sync.yml` with `apply=true`, for example at `7 * * * *`.
Keep the AFAS token in the scheduler's secret store.

**Provisioning logs.** Also run `check-logs --since-minutes 60` every hour, a quarter after
the sync (`deploy/ansible/run-check-logs.yml`). Exit 50 means Microsoft rejected records,
for example because of a UPN conflict.

**Checkmk.** `deploy/ansible/checkmk/afas_entra_sync` is a local check: OK on exit 0, WARN
on exit 3, CRIT on any other exit code, a broken report, or no run for more than 3 hours.
A manual dry-run overwrites the report; the status then shows `(dry-run)`.

**Exit codes:**

| Code | Meaning | What to do |
| --- | --- | --- |
| 0 | All good | Nothing |
| 3 | Done, but records need attention | `exclusions` and `disappeared_while_active` to HR |
| 10 | Configuration error | Run `check-config` |
| 11 | Another run is active | Double scheduling? |
| 20 | Safety stop, nothing uploaded | Read the report; cause in AFAS data or threshold |
| 30 | AFAS error | Token, GetConnector, reachability |
| 40 | Sign-in to Entra failed | Certificate expired? Permissions? |
| 41 | Upload failed | The next run repairs it; if it persists, see troubleshooting |
| 50 | `check-logs`: Microsoft reports failures | Read the failure lines |
| 60 | `check-tls`: an endpoint fails the TLS policy | Network, proxy or TLS inspection |

**Daily limit.** With P1, Microsoft allows 2,000 calls per day, at most 50 employees per call.
Example with 600 employees and a run every hour:

- 600 employees ÷ 50 per call = 12 calls per run
- 12 calls × 24 runs per day = 288 calls per day
- 288 is well below 2,000, so running every hour is fine

**Recurring work.**

| What | When | How |
| --- | --- | --- |
| Excluded records to HR | On exit 3 | `exclusions` and `disappeared_while_active` from the report |
| Renew the certificate | A month before expiry | Step 3a again, upload the new `cert.pem`, remove the old one only after a successful run |
| Renew the AFAS token | When AFAS revokes it, or when staff change | Replace the token file (or secret) |
| New version | On release | Replace the binary (Ansible verifies the checksum) |
| Check TLS | After network or firewall changes | `check-tls` |
| Provisioning agent | Updates itself | In the app under View on-premises agents |

## Employees: joiners, movers and leavers

HR does everything in AFAS; the account follows within an hour. The examples assume the
defaults: create 14 days in advance and keep sending 30 days after the end date.

| What HR does in AFAS | What happens to the account |
| --- | --- |
| New employee, starts in 3 weeks | Nothing yet |
| Start date is 14 days away or less | Account created in the target OU, disabled |
| Start date reached | Account enabled |
| Job title, department, manager or cost center changed | Only those fields updated |
| Name changed, new UPN in AFAS | Name and UPN updated |
| End date filled in, not reached yet | Account stays active |
| Day after the end date | Account disabled, not deleted |
| 30 days after the end date | No longer sent; account stays disabled |
| Rehired, same employee number | Existing account enabled again |
| Data error (invalid UPN, date, field too long) | That record stays unchanged; listed in `exclusions` |
| Employee disappears from the GetConnector | Account stays as it is; listed in `disappeared_while_active` |

Dates are whole calendar days in `policy.timezone`. Someone leaving on 31 December is still
active that day and disabled on 1 January.

**Password and first sign-in.** The tool and Microsoft set a random password nobody knows.
Arrange the first sign-in yourself, for example the service desk issuing a Temporary Access
Pass on day 1, or Lifecycle Workflows (Entra ID Governance).

**Clean-up.** Disabled accounts stay. Delete them after X months with your existing
process; the tool and this Microsoft API never delete.

## Groups

Groups do not go through the tool but through the Entra ID integration in AFAS Profit. HR
manages user groups and members there; AFAS carries them to Entra groups. Rights and
licences are assigned to those groups in Entra.

How the AFAS integration works:

- It runs from the AFAS cloud and calls Microsoft Graph with an app registration you create
  for it. Use a separate app registration (e.g. `afas-profit-groups`), never the tool's.
  Ask AFAS or your partner which Graph permissions it needs, and grant no more.
- A Profit user group is linked one-to-one to an Entra group, or AFAS creates a new Entra
  group with the same name.
- Members are matched on the UPN of the Profit user. Without a UPN, someone is skipped.
- AFAS is leading: anyone added to such a group by hand in Entra is removed at the next sync.
- On leaving, AFAS removes the user from the linked groups.

Rules for combining it with this tool:

- **The UPN comes from AFAS.** The tool sends the same UPN to AD, so the group integration
  always matches the account the tool created.
- **Cloud groups only.** Groups synchronised from on-prem AD cannot be changed in Entra.
- **Account first, group second.** According to AFAS, the integration creates missing Entra
  users itself. If that happens before the AD account reaches Entra through Connect Sync,
  you get a second, cloud-only account. Prevent it:

  | Measure | How |
  | --- | --- |
  | Create accounts earlier | Set `prehire_days` to the period in which HR usually onboards (e.g. 30 or 60 days) |
  | Agree the order | HR adds a new employee to groups only when the UPN exists in AFAS and the account exists |
  | Test | Test case in the pilot: one new employee, one account |
  | Ask AFAS | Whether automatic user creation can be turned off |

- **Disabling is done by the tool.** In a hybrid environment AD decides whether an account
  is enabled, so disabling on leaving comes from the tool, not from AFAS.
- **Naming.** Give linked groups a prefix, e.g. `AFAS-`, and do not change them by hand.
  Exceptions get their own, unlinked group.
- **Licences.** Use group-based licensing in Entra (included in P1).

**Without the AFAS integration: dynamic groups.** Entra can fill groups from the attributes
the tool sends, e.g. `user.department -eq "ICT"`, or a job profile through the
`job_profile` toggle. Included in P1, no second integration.

**On-prem rights (file shares).** AFAS groups exist only in Entra. For on-prem rights keep
using AD groups, or later write groups back to AD with Cloud Sync. That is a separate project.

**Only some employees.** That is not done with groups but in two other places:

| Where | How | When |
| --- | --- | --- |
| Filter in the AFAS GetConnector | e.g. own staff only | Permanent: who belongs structurally |
| Scoping filter in the provisioning app (step 2c) | e.g. `department EQUALS ICT` | Temporary: pilot, phased roll-out |

Careful with the AFAS filter: someone who drops out while active is not disabled. They show
up in `disappeared_while_active` and the run ends with exit 3.

## Admin GUI (optional)

Off by default. Turn it on with `[gui] enabled = true` (Ansible: `gui_enabled: true`). It
runs on `127.0.0.1:8080`; reach it through an SSH tunnel and sign in with the link in
`/var/lib/afas-entra-sync/gui-login-url`. Behind Traefik with Authentik use
`--trusted-proxy`. Turn it off in the GUI itself or in the config; `gui-enable` on the server
turns it back on. Details: README and SECURITY.md.

## Troubleshooting

Start with `/var/lib/afas-entra-sync/last-report.json`, then the provisioning logs in Entra.

| Symptom | Cause | Fix |
| --- | --- | --- |
| Exit 20, `min_records` or `max_drop_percent` | AFAS returned far fewer employees than expected | Check the GetConnector filter or an AFAS outage; change the threshold only if the drop is real |
| Exit 20, `max_disables_per_run` | Many disables at once | Check the list in the report; if right, once `sync --apply --allow-mass-disable` |
| Exit 20, `max_invalid_percent` | Many data errors; often a wrong field name or date format | Read `exclusions`, check `[afas.fields]` |
| Exit 30, "field … is missing" | Field name in config does not match the GetConnector | Fix the name in config or GetConnector |
| Exit 30, HTTP 401 from AFAS | Token invalid or not linked to the app connector | New token, step 1b |
| Exit 10, "accessible by group or others" | Token file or private key too open | `chmod 600` and owner `afas-sync` |
| Exit 40, AADSTS700027 | Certificate does not match the one in Entra | Upload `cert.pem` again |
| Exit 40, AADSTS7000222 or expired | Certificate or secret expired | New certificate (step 3a) |
| Exit 41, HTTP 403 | Permission or admin consent missing | Step 3b |
| Exit 41, HTTP 400 | Wrong job ID or service principal ID | Copy again from step 2e |
| Exit 60 or "TLS handshake failed" | Endpoint, proxy or firewall does not meet `[tls]` | `check-tls`; exclude the hosts from TLS inspection, or set `min_version = "1.2"` only if an endpoint really lacks TLS 1.3 |
| Exit 3, `disappeared_while_active` | Employee no longer in the GetConnector | Intentional? Disable the account yourself. Otherwise fix the filter |
| Upload OK but nothing in the provisioning logs | Job paused, in quarantine, or agent offline | Enterprise app → Provisioning: status and agent; logs lag 5–10 minutes |
| Job in quarantine | Notification email empty, or accidental deletion threshold hit | Fill in the email or review the staged deletes, then Restart |
| Duplicate account in AD | `employeeID` was empty at go-live | Disable the duplicate, set `employeeID` on the right account (step 5) |
| User missing from an AFAS group in Entra | UPN in AFAS differs from the real UPN, or the account did not exist yet | Align the UPN; wait for the next AFAS sync |

Every run sends the full current list, so a missed or failed run repairs itself with the
next one; nothing needs to be caught up.

## Rolling back

Nothing in this setup deletes accounts or changes Entra Connect Sync. Rolling back means
stopping, not restoring.

**Emergency stop:** turn off the schedule, and in the Enterprise app choose Stop
provisioning. Uploads to a stopped job pile up until Microsoft refuses them ("bucket full"),
so always stop both. Optionally unlink AFAS groups in Profit.

**What stays:** accounts the tool created and attributes it updated. Accounts it disabled stay
disabled. Repair per case in AD; the report and provisioning logs show what happened when.

**Remove completely:** delete the provisioning app and the `afas-entra-sync` app
registration in Entra, uninstall the agent, and on the Linux host remove
`/usr/local/bin/afas-entra-sync`, `/etc/afas-entra-sync`, `/var/lib/afas-entra-sync` and the
`afas-sync` user. `employeeID` on the accounts may stay.

## References

- Microsoft Learn: API-driven inbound provisioning concepts, Configure API-driven inbound
  provisioning app, Grant access to the inbound provisioning API, FAQ, Troubleshoot
  inbound provisioning API
- Microsoft Learn: Prevent accidental deletions; Cloud Sync prerequisites (provisioning agent);
  Cloud Sync FAQ (agent on the Connect Sync server); Entra Connect Sync scheduler
- Microsoft: index employeeID in AD
- AFAS Help: Calling a connector through the Profit REST service; Synchronising user groups
  with Entra ID
