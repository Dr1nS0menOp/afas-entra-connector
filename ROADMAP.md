# Roadmap afas-entra-sync

Recorded 2026-10-31, starting from version 0.1.0 (PoC): employees from one GetConnector,
a fixed set of attributes, CLI only. Current version: 0.9.1 (plain-language texts; 0.9.0: optional modules: roles and licences, first sign-in code for new hires (joiners), actions for departing employees (leavers), webhook, access log, exceptions).

Order = proposed build order. Every item ships with tests at the same level as 0.1.0
(unit, e2e against mocks, property tests, mutation tests).

---

## 1. Attributes with on/off toggles — BUILT in 0.2.0 / 0.3.0

Built: `phone_work`, `phone_mobile`, `office`, `company`, `employee_type`, `job_profile`,
work address (`street`, `postal_code`, `city`, `country`), `send_hire_date`, `send_leave_date`,
with tests in `tests/extra.rs`.

Still open:
- Cost center to an `extensionAttributeX` (needs a schema extension in the provisioning app).
- Check whether hire/leave date reach Entra through AD + Connect Sync (needed for
  Lifecycle Workflows); if not, find an alternative.

Notes:
- Required fields (employee number, names, UPN, dates) stay outside the toggles.
- Microsoft only processes `type = "work"` for phone and address (known limitation).
- Turning a toggle off = no longer sent. The value in AD stays, unless "clear attribute
  values" is on in the provisioning app. The GUI says this explicitly.

## 2. Populations: contractors, externals, interns — BASE BUILT in 0.3.0

Built: `[population]` with `name`, `id_prefix` and a fixed `employee_type`; one config per
population (own GetConnector, own `state.dir`, preferably its own provisioning app).

Still open:
- Manager links across populations.
- Required end date (or maximum duration) for externals.
- Hard check that no `externalId` appears in two populations.

## 3. Job profiles to groups — OPTION A BUILT in 0.3.0, OPTION C BUILT in 0.9.0

Built: toggle `job_profile` (→ `jobProfile`). Groups through dynamic membership rules in
Entra; see README.

| Option | How | Pro | Con |
| --- | --- | --- | --- |
| A | Send the job profile (code) as an attribute; dynamic groups in Entra | No extra permissions for the tool; Entra does the work | Groups managed per rule in Entra; dynamic group delay |
| B | HR links job profiles to AFAS user groups; native AFAS integration | No code; HR manages it | Depends on the AFAS integration; it matches on UPN and runs from the AFAS cloud |
| C | Tool manages membership of cloud groups through Graph, from a job profile → group mapping | Fully in our hands, same safety model (thresholds, dry-run) | Tool needs `GroupMember.ReadWrite.All`; cloud groups only; more build and test work |

- Option C is the `[roles]` module (0.9.0), with the safeguards below, conflicting groups (segregation of duties) and exceptions. A and C can be combined per group.
- With C: only manage groups with a fixed prefix, never role-assignable, mail-enabled or
  on-prem groups; threshold on membership changes per run.

## 4. Web GUI (optional) — COMPLETE in 0.5.0

- `serve` starts the GUI; it covers every setting and every action of the CLI
  (dry-run with date and payload download, sync with typed confirmation, check-config,
  check-logs).
- Master switch `[gui] enabled` in the config file, off by default. The GUI can turn itself
  off but never on; `gui-enable` on the server turns it back on.
- Layered config: the GUI writes `<state.dir>/overrides.toml`, Ansible owns the base file.
  Locked keys (token sources, tenant, app, certificate paths, login/Graph addresses, state
  directory, GUI switch) are read-only in the GUI.
- Security: localhost by default, otherwise only behind a trusted proxy with the Authentik
  user header; CSRF token, read-only mode, strict CSP, no JavaScript, audit log.
- 20 GUI tests plus visual review (light, dark, mobile).

Possible later additions: dry-run diff per attribute, certificate expiry warning,
CSV export of exclusions.

## 5. Smaller items

- ~~Revoke sessions on disable~~: built in 0.9.0 as the `[leaver]` module.
- Document display name from AFAS name usage (partner name / birth name) via `display_name`.
- Optional OU per department/population via a `parentDistinguishedName` expression in the
  provisioning app.
- Warning in report/GUI when the certificate expires within 30 days.
- Optional native TLS for the GUI itself (now: local only or behind Traefik).
- Clear secrets from memory after use (zeroize).
- Extend mutation tests to `config.rs` and `web.rs`.

## 6. Modules — BUILT in 0.9.0

Coverage of what commercial AFAS → Entra/AD connectors usually offer:

| Capability | Status |
| --- | --- |
| Accounts create/update/disable from AFAS (AD and cloud) | Core, since 0.1.0 |
| Accounts before the start date (pre-hires), window after the end date, staff categories (populations) | Core, since 0.3.0 |
| Groups and licences from HR data, with conflicting groups (SoD) and exceptions | `[roles]`, 0.9.0 |
| New hires (joiners): first sign-in without a password (Temporary Access Pass to the manager) | `[joiner]`, 0.9.0 |
| Departing employees (leavers): sign out everywhere, automatic reply | `[leaver]`, 0.9.0 |
| ITSM tickets / workflows for new hires, job changes, departing employees | `[webhook]`, 0.9.0 |
| Access history and export for audits | Access log + `report`, 0.9.0 |
| Admin GUI, audit log | 0.5.0 |
| Mailbox to shared mailbox | Through the webhook (no Graph API) |

Still open:
- Writing values back to AFAS (e.g. the created UPN or email) through an UpdateConnector.
- Access review page in the GUI (per group: members, since when, through which rule).
- Teams/SharePoint site membership (beyond groups).
- Manager notification on movers (now via the webhook).
- Certificate expiry warning in report and GUI.

## Questions to settle per deployment

1. Where are contractors, externals and interns kept in AFAS, and do they have a unique number?
2. Which AFAS fields hold phone, mobile, office and job profile?
3. Job profiles: option A, B or C?
4. Should populations go to separate OUs and/or separate provisioning apps?
5. GUI: who gets access, and is it IT only or HR too?
