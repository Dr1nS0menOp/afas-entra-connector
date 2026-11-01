# Modules: roles, new hires, departing employees and webhook

The core of afas-entra-sync delivers accounts to Entra provisioning. The four optional
modules handle what usually comes next when someone starts, changes jobs or leaves
(the joiner, mover and leaver process, JML):

| Module | What it does | Microsoft Graph permissions (application) |
| --- | --- | --- |
| `[roles]` Roles and licences | Group membership from HR data (department, job profile, office, ...); licences through group-based licensing; conflicting groups (segregation of duties); time-limited exceptions | `GroupMember.ReadWrite.All`, `User.Read.All` |
| `[joiner]` New hires (joiners) | First sign-in code (Temporary Access Pass, TAP), valid from the start date, mailed to the manager or a fixed address | `UserAuthMethod-TAP.ReadWrite.All`, `User.Read.All`; `Mail.Send` through Exchange RBAC for Applications, scoped to the sender mailbox |
| `[leaver]` Departing employees (leavers) | After the end date: sign out on every device and set an automatic reply | `User.RevokeSessions.All`, `User.Read.All`, `MailboxSettings.ReadWrite` |
| `[webhook]` Webhook | Events for new hires, job changes and departing employees (joiner, mover, leaver) as signed JSON for an ITSM tool, Power Automate or a script | none (HTTPS POST to your endpoint) |

Each module is off until you add its section to the config file. The config sections and
webhook event names use the short HR terms (`joiner`, `mover`, `leaver`); the GUI and this
document use plain words with the HR term in brackets. Example sections are at
the end of `afas-entra-sync.example.toml`.

## Principles

The modules follow the same rules as the core:

- **Own app registration per module.** A module signs in with its own app registration and
  certificate. If one is compromised, the others are not. The provisioning app
  (`SynchronizationData-User.Upload`) gets none of these permissions.
- **Plan first, then act.** Without `--apply` a module only plans. The report shows every
  planned change (`modules.<name>.planned`).
- **Own maximum per run.** If a module would change more than its maximum, it changes
  **nothing** and reports a violation (exit 21). A broken AFAS filter or a wrong rule cannot
  empty all groups or mail 500 sign-in codes.
- **Only after a good upload.** The modules run only when the provisioning run did not
  stop (no exit 10, 11, 20, 30, 40 or 41). The order is: departing employees, new hires, roles, webhook.
- **Matching is strict.** An employee is linked to an Entra account by `employeeId`. Only if
  the Entra account has no `employeeId` is the UPN used. Two accounts with the same
  `employeeId` is a conflict: the modules skip that employee and say so.
- **Everything is logged.** Every group change, sign-in code and action for a departing employee goes to the access
  log (`<state.dir>/access.log`, JSON Lines, mode 0600). The value of a Temporary Access Pass
  is never logged or written to disk.

### Exit codes

| Code | Meaning |
| --- | --- |
| 3 | Completed, but something needs attention: conflicting groups (segregation of duties), an employee without an Entra account yet, a matching conflict. See `notes` in the report. |
| 21 | A module stopped itself: more changes than its maximum. Nothing changed by that module. |
| 42 | A module failed: sign-in, Graph error or webhook delivery. Details in the report. |

When several apply, the highest wins (42 over 21 over 3).

## Setting up an app registration for a module

Do this once per module you use (`afas-entra-sync-roles`, `-joiner`, `-leaver`).

1. Create a certificate on the Linux host, as root:

   ```
   cd /etc/afas-entra-sync
   openssl req -x509 -newkey rsa:3072 -sha256 -days 730 -nodes \
     -subj "/CN=afas-entra-sync-roles" -keyout roles-key.pem -out roles-cert.pem
   chown afas-entra-sync: roles-key.pem roles-cert.pem
   chmod 0600 roles-key.pem
   ```

2. In Entra: *App registrations → New registration*, single tenant, no redirect URI.
3. *Certificates & secrets → Certificates → Upload* `roles-cert.pem`. No client secret.
4. *API permissions → Add → Microsoft Graph → Application permissions*: the permissions
   from the table above, then *Grant admin consent*.
5. Fill in `client_id`, `certificate_pem` and `private_key_pem` in the module section.
6. Test run (dry-run): `afas-entra-sync -c config.toml sync`. Check `modules` in the report.

The tenant, login and Graph addresses come from `[entra]`.

## Roles and licences

```toml
[roles]
enabled = true
client_id = "..."
certificate_pem = "/etc/afas-entra-sync/roles-cert.pem"
private_key_pem = "/etc/afas-entra-sync/roles-key.pem"
group_prefix = "AFAS-"

[[roles.rule]]
group_id = "22222222-2222-2222-2222-222222222222"
name = "AFAS-Finance"
department = ["Finance", "Control"]
```

**Rules.** An employee gets a rule's group when they match **all** non-empty criteria of
that rule. Values within one criterion are alternatives (OR), compared case-insensitively.
Criteria: `department`, `job_title`, `job_profile`, `office`, `company`, `employee_type`,
`cost_center`, `population` (staff category). `all = true` matches everyone in the upload. A group can appear
in several rules; matching any of them is enough.

**Who is eligible.** Active employees. New hires before their start date (pre-hires) only
with `include_prehires = true` (licences cost money from the moment of assignment).
Departing employees (leavers) keep their groups for `keep_leavers_days` after their end
date, then they are removed. `keep_leavers_days` must be smaller than
`policy.leaver_lookback_days`: after that window a departing employee is no longer in the
upload, and the module would never see them again to remove them.

**Which groups can be managed.** The module checks every group in the rules before it
changes anything. If one group fails a check, the roles module changes **nothing** in that
run (exit 42) and names the group. A group fails when it:

- does not start with `group_prefix`;
- is role-assignable (`isAssignableToRole`): membership of those must stay with PIM;
- is synchronised from on-prem AD (cannot be changed in Entra);
- is a dynamic group.

Use cloud security groups created for this purpose, e.g. `AFAS-Finance`.

**Members the module does not know.** Accounts in a managed group that are not linked to an
employee in this upload (admin accounts, service accounts, another staff category) are left
alone. Set `remove_unknown_members = true` only when the group must contain HR employees
only.

**Licences.** Assign licences to the managed groups in Entra (*Groups → group → Licenses*,
group-based licensing, included in Entra ID P1). The module never assigns licences directly,
so no licence permission is needed and Entra handles conflicts and reporting.

**Conflicting groups (segregation of duties).**

```toml
[[roles.sod]]
name = "Pay and approve"
groups = ["<payments group id>", "<approval group id>"]
```

When the rules would give one person two or more groups from the same conflict rule (`[[roles.sod]]`), the module
leaves that person's membership of those groups as it is (it neither adds nor removes them),
reports it in `notes` and the run ends with exit 3. Fix the HR data or the rules, or add an
`exclude` exception for one of the groups. Someone who is already in two such groups by
hand is reported too. Every group in a conflict rule must also be in a role rule.

**Exceptions.** A manual, time-limited deviation, with a reason:

```
afas-entra-sync -c config.toml exception add --employee 10422 \
  --group 22222222-2222-2222-2222-222222222222 --kind include \
  --until 2026-12-31 --reason "Year-end close support"
afas-entra-sync -c config.toml exception list
afas-entra-sync -c config.toml exception remove <id>
```

`include` keeps or puts someone in a group, `exclude` keeps them out. At most one year
ahead. After the end date the rules apply again at the next run. Exceptions are stored in
`<state.dir>/exceptions.json` and can also be managed on the *Exceptions* page of the GUI.
Adding and removing is audited.

Exceptions use the employee number as it appears in the report, including the staff
category prefix (population `id_prefix`), and only groups from the role rules. Both the CLI
and the GUI check this.

**Job changes (movers).** Someone who changes department loses the old group and gets the
new one in the same run. Combined with group-based licensing and Conditional Access on
groups, that covers the whole job change.

## New hires (joiners): first sign-in code

```toml
[joiner]
enabled = true
client_id = "..."
certificate_pem = "/etc/afas-entra-sync/joiner-cert.pem"
private_key_pem = "/etc/afas-entra-sync/joiner-key.pem"
sender = "onboarding@example.com"
deliver_to = "manager"
fixed_address = "servicedesk@example.com"
```

From `days_before_start` days before the start date, the module creates a first sign-in
code (Temporary Access Pass) for the new account. The code works from `start_hour` (local time, `policy.timezone`)
on the start date, for `lifetime_minutes` (10 to 43,200). The new colleague uses it to sign
in for the first time and register MFA or a passkey, without a password ever being sent.

- **Who receives it.** `deliver_to = "manager"`: the manager's email from AFAS. If the
  manager has no email, `fixed_address` is used; without one, no code is sent and the
  report says why. `deliver_to = "fixed"`: always `fixed_address`, for example the service
  desk.
- **Once per start date.** A code is sent once per employee per start date. Returning
  employees (rehires) get a new one. If the account is not in Entra yet (provisioning still busy), the next run tries
  again, up to three days after the start date.
- **Mail fails, code removed.** If the mail cannot be sent, the code is deleted again so no
  unknown code stays valid. If Graph does not answer clearly whether it created the code
  (network error or server error), the request is not repeated and any code that appeared
  is removed; the next run tries again.
- **Never replaced.** An account can have only one code. If the new hire already has a
  usable or future one (for example from the service desk), the module leaves it, sends
  nothing and reports it in `notes`; delete it in Entra to have a new one sent. An expired
  or already used code is removed first.
- **Never to a manager who has left.** If the manager in AFAS is no longer active, the
  code goes to `fixed_address` (or is not sent, without one): a departed manager's mailbox
  may be shared with others by then.
- **The template.** `subject` and `body` with placeholders `{display_name}`, `{upn}`,
  `{tap}` (the code), `{valid_from}`, `{valid_until}`, `{start_date}`. The body must contain `{tap}`.
- **Tenant setting.** Turn on the Temporary Access Pass method under *Protection →
  Authentication methods → Policies* for the users who need it.

**Restrict `Mail.Send` to the sender mailbox.** `Mail.Send` granted in Entra allows sending
as *every* mailbox. Do **not** grant it there. Grant it through Exchange Online RBAC for
Applications, scoped to the sender mailbox only:

```powershell
Connect-ExchangeOnline
# Service principal of the joiner app (Object ID from Enterprise applications)
New-ServicePrincipal -AppId <client id> -ObjectId <enterprise app object id> -DisplayName "afas-entra-sync-joiner"
New-ManagementScope -Name "afas-entra-sync sender" `
  -RecipientRestrictionFilter "PrimarySmtpAddress -eq 'onboarding@example.com'"
New-ManagementRoleAssignment -App <client id> -Role "Application Mail.Send" `
  -CustomResourceScope "afas-entra-sync sender"
Test-ServicePrincipalAuthorization -Identity <client id> -Resource onboarding@example.com
```

## Departing employees (leavers)

```toml
[leaver]
enabled = true
client_id = "..."
certificate_pem = "/etc/afas-entra-sync/leaver-cert.pem"
private_key_pem = "/etc/afas-entra-sync/leaver-key.pem"
auto_reply = "{display_name} no longer works here. Please contact {manager_name} ({manager_email})."
```

From the day after the end date (and up to `grace_days` later), once per end date:

1. **Sign out everywhere** (`revokeSignInSessions`, on by default). The account itself is
   disabled by provisioning; revoking makes refresh tokens on phones and laptops invalid
   too.
2. **Automatic reply**, when `auto_reply` is set. Placeholders `{display_name}`,
   `{manager_name}`, `{manager_email}`. Internal only, unless `auto_reply_external = true`.
   An account without a mailbox is not an error.

Removal from groups (and so licences) is done by the roles module, after
`keep_leavers_days`. The module needs `policy.leaver_lookback_days` of at least 1, since it
acts on departing employees that are still in the upload. The automatic reply is shown as
HTML by Exchange; the tool escapes the text and keeps its line breaks.

To keep `MailboxSettings.ReadWrite` narrower than the whole tenant, you can grant it with
Exchange RBAC for Applications too (role `Application MailboxSettings.ReadWrite`) with a
scope on user mailboxes, the same way as `Mail.Send` above.

**Not possible through Graph: converting the mailbox to a shared mailbox.** Microsoft offers
that only in Exchange Online PowerShell (`Set-Mailbox -Type Shared`). Use the webhook's
`leaver` event (departing employee) to create that task in your ITSM tool, or run it from an Azure Automation
runbook that receives the webhook.

## Webhook

```toml
[webhook]
enabled = true
url = "https://itsm.example.com/hooks/afas"
secret_env = "AFAS_ENTRA_WEBHOOK_SECRET"
events = ["joiner", "mover", "leaver"]
```

Events are found by comparing with the previous applied run. The first run only records a
baseline and sends nothing. The same happens when the previous comparison is older than 7
days (for example after the modules were off for a while), so no stale events are sent.

| Event | When |
| --- | --- |
| `joiner` | New hire: new employee in the upload, or a returning employee who is active again (`"rehire": true`) |
| `mover` | Job change: department, job title, job profile, office, company, employee type, cost center, manager, UPN or display name changed; `changes` holds old and new values |
| `leaver` | Departing employee: was active, now past the end date |

Each event is a POST with `Content-Type: application/json`:

```json
{
  "id": "6f1c2b0e-...",
  "event": "mover",
  "created_utc": "2026-11-01T06:05:12Z",
  "employee_id": "10388",
  "rehire": false,
  "employee": { "upn": "j.jansen@example.com", "display_name": "J. Jansen", "department": "ICT", "...": "..." },
  "changes": { "department": ["Finance", "ICT"] }
}
```

Headers:

| Header | Content |
| --- | --- |
| `X-AfasEntraSync-Event` | `joiner`, `mover` or `leaver` |
| `X-AfasEntraSync-Delivery` | The event id; use it to drop duplicates |
| `X-AfasEntraSync-Timestamp` | Unix time of sending |
| `X-AfasEntraSync-Signature` | `sha256=<hex HMAC-SHA256 of "<timestamp>.<body>">` |

**Delivery.** Any 2xx is delivered. Otherwise the event stays in the send queue
(outbox, in `modules-state.json`) and is sent again at the next run, in order: after the first failure
the rest waits. At most 10,000 events are kept. Delivery is at least once, so de-duplicate
on the event id.

**Verify the signature** on the receiving side, and refuse messages older than five
minutes. Python example:

```python
import hmac, hashlib, time

def verify(secret: bytes, headers, body: bytes) -> bool:
    ts = headers["X-AfasEntraSync-Timestamp"]
    if abs(time.time() - int(ts)) > 300:
        return False
    expected = "sha256=" + hmac.new(secret, ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, headers["X-AfasEntraSync-Signature"])
```

The secret comes from `secret_env` or `secret_file` (mode 0600), at least 16 characters.
Generate one with `openssl rand -hex 32`. The webhook uses the same TLS policy as the rest
(`[tls]`).

## Access log and reports

Every change a module made, successful or not. If the log cannot be written, the module
reports a failure (exit 42), because the audit trail would be incomplete.

```
afas-entra-sync -c config.toml report                       # JSON, everything
afas-entra-sync -c config.toml report --employee 10388      # one employee
afas-entra-sync -c config.toml report --since 2026-01-01 --csv > access.csv
```

Columns: time (UTC), module, action, employee number, UPN, target (group or mail recipient),
ok, detail, actor (`systemd`, `cli` or `gui:<user>`). The CSV is safe to open in a
spreadsheet: cells that start with `=`, `+`, `-` or `@` are prefixed so they are not run as
formulas. The GUI has the same on the *Access log* page, with a download.

Use it for audits ("who had access to Finance on 1 March, and why") and for access reviews.

## GUI

With the GUI on, the *Modules* page shows the status of each module, the role rules and the
conflicting groups; *Roles and licences*, *New hires (joiners)* and *Departing employees
(leavers)* let you change the non-sensitive
settings (maximums, days, templates); *Access log* and *Exceptions* are described above.
App registrations, certificates, `group_prefix`, the sender, the fixed address and the
webhook are locked: they can only be changed in the config file.

## Not yet verified

These are based on Microsoft documentation and tested against simulated endpoints:

1. Temporary Access Pass creation with a future `startDateTime` in your tenant's policy.
2. `sendMail` with RBAC for Applications scoping.
3. The `MailboxNotEnabled` error code for accounts without a mailbox.
4. Delays between provisioning creating an account and it being visible in Graph (the
   new-hires module retries for three days).
