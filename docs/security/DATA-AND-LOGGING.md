# Data classification and log inventory

Covers OWASP ASVS 5.0 V14.1 (data classification and protection), V14.2.4 (handling rules)
and V16.1.1 (log inventory). Last reviewed 2026-11-01 (version 0.10.0).

## Data classes

| Class | What | Protection |
| --- | --- | --- |
| **Secret** | AFAS token, Entra private keys and optional client secret, webhook secret, OAuth access tokens, GUI session ids, login link and form token, first sign-in codes (Temporary Access Pass) for new hires | Never in the config file, never logged, never in reports. Files 0600 and ownership-checked; tokens and codes only in memory. TLS 1.3 in transit. The first sign-in code exists only in the Graph response and the mail to the manager. |
| **Personal** | Employee records from AFAS: names, UPN, email, employee number, job title, department, manager, cost center, start and end dates; optionally phone, office, company, employee type, job profile, work address | In memory during a run. Stored only where listed below, in the state directory (0700, service user). Sent only to Microsoft (provisioning, Graph) and, when configured, to the webhook receiver. |
| **Internal** | Configuration without secrets, run reports, audit and access logs, administrator user names | State and config directories 0700, files 0600. |

The program sends nothing to third parties beyond AFAS (reading), Microsoft Entra and Graph,
and the webhook URL you configure. The GUI loads no external resources.

## Where personal data is stored

| File (in `state.dir`) | Content | Retention |
| --- | --- | --- |
| `state.json` | Per employee: employee number and whether the account was active | Overwritten every applied run |
| `modules-state.json` | Per employee: the attributes the modules compare (UPN, name, department, job, manager, dates); first-sign-in and leaver bookkeeping (employee number and a date); webhook send queue with employee snapshots | Overwritten every applied run; bookkeeping entries older than 60 (codes) or 400 (leavers) days are dropped; the send queue holds at most 10,000 events |
| `last-report.json` | Employee numbers with reasons (skipped, missing, warnings); module actions with UPN | Overwritten every run |
| `access.log` | Every module change: time, module, action, employee number, UPN, target group or mail address, result, actor | Append-only; rotate and keep according to your retention policy for access records (see below) |
| `audit.log` | GUI actions: time, administrator, action, detail | Append-only; same as access.log |
| `exceptions.json` | Exceptions: employee number, group, until, reason, who | Until removed; expired ones can be deleted |
| `payload.json` | The exact upload, only when requested in a test run | Delete after use (GUI button); never written by a normal run |

Rules:

- Reports and logs identify employees by number (and UPN where an action needs it), not by
  name.
- Do not copy `payload.json` off the server; it contains every employee's record.
- Retention: decide with your privacy officer how long `access.log` and `audit.log` are
  kept (they are the evidence for access reviews), and rotate them, for example with
  logrotate using `copytruncate`.

## Log inventory

| Log | Written by | Location | Format | Events | Readable by |
| --- | --- | --- | --- | --- | --- |
| Process log | All commands | stderr → journald (`journalctl -u afas-entra-sync*`) | Text, one event per line | Run start and end, errors with cause, TLS and sign-in failures, warnings. No secrets. | root, journal readers |
| Run report | `sync` | `last-report.json` and stdout | JSON | Counts, thresholds, skipped records, missing employees, upload result, module results | Service user |
| Audit log | GUI | `audit.log` | JSON Lines, UTC timestamps | Sign-in, refused sign-in (wrong or expired link), refused session (unknown or expired), refused form token, sign-out, settings changes, runs, exports, exceptions added or removed, GUI switched off | Service user |
| Access log | Modules | `access.log` | JSON Lines, UTC timestamps | Group added or removed, first sign-in code sent, leaver actions, with result | Service user |
| Provisioning logs | Microsoft | Entra admin center; `check-logs` | — | What Microsoft did with each record | Entra administrators |

Every line is JSON-encoded, so data cannot break a line or forge an entry.

## Shipping logs to a separate system

ASVS V16.4.3 asks for logs on a separate system, so that a compromised host cannot erase
them. Forward:

- journald, with your usual agent (for example a Graylog Sidecar or rsyslog to Graylog);
- `audit.log` and `access.log`, as JSON files (for example Filebeat or the Graylog Sidecar
  with a JSON input).

Alert at least on: `login refused` more than a few times, `form token refused`, exit codes
other than 0 and 3, and `access log not written`.

Keep the host clock synchronised (chrony or systemd-timesyncd); all timestamps are UTC.
