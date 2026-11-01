# Roadmap afas-entra-sync

Recorded 2026-10-31, starting from version 0.1.0 (PoC): employees from one GetConnector,
a fixed set of attributes, CLI only. Current version: 0.7.0 (security hardening: TLS 1.3 + post-quantum, check-tls, GUI sign-in, secret file checks; see SECURITY.md).

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

## 3. Job profiles to groups — OPTION A BUILT in 0.3.0

Built: toggle `job_profile` (→ `jobProfile`). Groups through dynamic membership rules in
Entra; see README.

| Option | How | Pro | Con |
| --- | --- | --- | --- |
| A | Send the job profile (code) as an attribute; dynamic groups in Entra | No extra permissions for the tool; Entra does the work | Groups managed per rule in Entra; dynamic group delay |
| B | HR links job profiles to AFAS user groups; native AFAS integration | No code; HR manages it | Depends on the AFAS integration; it matches on UPN and runs from the AFAS cloud |
| C | Tool manages membership of cloud groups through Graph, from a job profile → group mapping | Fully in our hands, same safety model (thresholds, dry-run) | Tool needs `GroupMember.ReadWrite.All`; cloud groups only; more build and test work |

- Current preference: **A**; C only if A falls short.
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

- Revoke sessions on disable (optional, needs `User.RevokeSessions.All`).
- Document display name from AFAS name usage (partner name / birth name) via `display_name`.
- Optional OU per department/population via a `parentDistinguishedName` expression in the
  provisioning app.
- Warning in report/GUI when the certificate expires within 30 days.
- Optional native TLS for the GUI itself (now: local only or behind Traefik).
- Clear secrets from memory after use (zeroize).
- Extend mutation tests to `config.rs` and `web.rs`.

## Questions to settle per deployment

1. Where are contractors, externals and interns kept in AFAS, and do they have a unique number?
2. Which AFAS fields hold phone, mobile, office and job profile?
3. Job profiles: option A, B or C?
4. Should populations go to separate OUs and/or separate provisioning apps?
5. GUI: who gets access, and is it IT only or HR too?
