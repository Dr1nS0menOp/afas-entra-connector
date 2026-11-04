// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The afas-entra-sync Authors
//! Usability: finding the config file, refusing to run as the wrong user, certificate
//! expiry, and readable summaries for people at a terminal.

use crate::config::{AuthMode, Config};
use crate::sync::Report;
use chrono::{DateTime, Utc};
use std::ffi::OsString;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// Where `install` puts the config.
pub const DEFAULT_CONFIG: &str = "/etc/afas-entra-sync/config.toml";
/// Overrides the default without typing `-c` every time.
pub const CONFIG_ENV: &str = "AFAS_ENTRA_SYNC_CONFIG";
/// Last resort: a config next to where the command runs.
pub const LOCAL_CONFIG: &str = "afas-entra-sync.toml";

/// `-c` wins; then `$AFAS_ENTRA_SYNC_CONFIG`; then the installed config if it exists;
/// then `./afas-entra-sync.toml`.
pub fn resolve_config(
    explicit: Option<PathBuf>,
    env: Option<OsString>,
    exists: &dyn Fn(&Path) -> bool,
) -> PathBuf {
    if let Some(p) = explicit {
        return p;
    }
    if let Some(e) = env.filter(|e| !e.is_empty()) {
        return PathBuf::from(e);
    }
    if exists(Path::new(DEFAULT_CONFIG)) {
        return PathBuf::from(DEFAULT_CONFIG);
    }
    PathBuf::from(LOCAL_CONFIG)
}

// ------------------------------------------------------------------ running user

/// The effective user id of this process (owner of /proc/self), without unsafe code.
pub fn effective_uid() -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata("/proc/self").ok().map(|m| m.uid())
}

pub fn owner_uid(p: &Path) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(p).ok().map(|m| m.uid())
}

/// User name for a uid from an /etc/passwd text.
pub fn user_name(passwd: &str, uid: u32) -> Option<String> {
    passwd.lines().find_map(|l| {
        let mut f = l.split(':');
        let name = f.next()?;
        let id: u32 = f.nth(1)?.parse().ok()?;
        (id == uid).then(|| name.to_string())
    })
}

/// Running as root while the state directory belongs to the service user would leave
/// root-owned files that the service can no longer change. Returns the message to show.
pub fn wrong_user(
    euid: Option<u32>,
    state_dir: &Path,
    state_owner: Option<u32>,
    owner_name: Option<&str>,
    args: &[String],
) -> Option<String> {
    let (Some(0), Some(owner)) = (euid, state_owner) else {
        return None;
    };
    if owner == 0 {
        return None;
    }
    let name = owner_name.map_or_else(|| owner.to_string(), str::to_string);
    let cmd = args
        .iter()
        .map(|a| shell_quote(a))
        .collect::<Vec<_>>()
        .join(" ");
    Some(format!(
        "do not run this as root: files in {} belong to the user '{name}', and files created by root would stop the service from writing them.\nRun it as that user instead:\n\n    sudo -u {name} {cmd}\n",
        state_dir.display()
    ))
}

fn shell_quote(s: &str) -> String {
    if !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./=:@,+".contains(c))
    {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

/// The check `main` runs before commands that write to the state directory.
pub fn check_running_user(cfg: &Config, args: &[String]) -> Result<(), String> {
    let dir = &cfg.state.dir;
    let owner = owner_uid(dir);
    let passwd = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
    let name = owner.and_then(|o| user_name(&passwd, o));
    match wrong_user(effective_uid(), dir, owner, name.as_deref(), args) {
        Some(m) => Err(m),
        None => Ok(()),
    }
}

// ------------------------------------------------------------------ certificates

/// Warn this many days before a certificate expires.
pub const CERT_WARN_DAYS: i64 = 30;
/// From this many days on, the run ends with exit 3 so monitoring raises it.
pub const CERT_ATTENTION_DAYS: i64 = 7;

/// Expiry date of the (first) certificate in a PEM file.
pub fn cert_not_after(pem: &[u8]) -> Result<DateTime<Utc>, String> {
    let (_, p) =
        x509_parser::pem::parse_x509_pem(pem).map_err(|e| format!("not a PEM certificate: {e}"))?;
    let c = p
        .parse_x509()
        .map_err(|e| format!("not an X.509 certificate: {e}"))?;
    DateTime::from_timestamp(c.validity().not_after.timestamp(), 0)
        .ok_or_else(|| "expiry date out of range".to_string())
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CertStatus {
    /// Which app registration uses it ("provisioning", "roles", ...).
    pub app: String,
    pub path: PathBuf,
    /// Expiry (UTC), or the error reading it.
    pub expires: Result<String, String>,
    pub days_left: Option<i64>,
}

/// Every certificate the configuration uses, with its expiry.
pub fn certificates(cfg: &Config, now: DateTime<Utc>) -> Vec<CertStatus> {
    let mut list: Vec<(String, PathBuf)> = Vec::new();
    if cfg.entra.auth == AuthMode::Certificate
        && let Some(p) = &cfg.entra.certificate_pem
    {
        list.push(("provisioning".into(), p.clone()));
    }
    if let Some(m) = cfg.roles.as_ref().filter(|m| m.enabled) {
        list.push(("roles".into(), m.identity().certificate_pem));
    }
    if let Some(m) = cfg.joiner.as_ref().filter(|m| m.enabled) {
        list.push(("new hires".into(), m.identity().certificate_pem));
    }
    if let Some(m) = cfg.leaver.as_ref().filter(|m| m.enabled) {
        list.push(("departing employees".into(), m.identity().certificate_pem));
    }
    if let Some(e) = cfg
        .notify
        .as_ref()
        .filter(|n| n.enabled)
        .and_then(|n| n.email.as_ref())
    {
        list.push(("notifications".into(), e.certificate_pem.clone()));
    }
    if let Some(c) = &cfg.preview.certificate_pem {
        list.push(("preview".into(), c.clone()));
    }
    list.into_iter()
        .map(|(app, path)| {
            let r = std::fs::read(&path)
                .map_err(|e| format!("cannot read: {e}"))
                .and_then(|b| cert_not_after(&b));
            CertStatus {
                app,
                days_left: r.as_ref().ok().map(|d| (*d - now).num_days()),
                expires: r.map(|d| d.format("%Y-%m-%d").to_string()),
                path,
            }
        })
        .collect()
}

/// The command that renews the certificate of this app registration.
pub fn renew_command(app: &str) -> &'static str {
    match app {
        "provisioning" => "sudo afas-entra-sync install --renew-cert",
        "roles" => "sudo afas-entra-sync module-setup roles --renew",
        "new hires" => "sudo afas-entra-sync module-setup joiner --renew",
        "notifications" => "sudo afas-entra-sync module-setup notify --renew",
        "preview" => "sudo afas-entra-sync module-setup preview --renew",
        _ => "sudo afas-entra-sync module-setup leaver --renew",
    }
}

/// Notices for certificates that expire within `CERT_WARN_DAYS` (or already did), and
/// whether one is within `CERT_ATTENTION_DAYS`.
pub fn cert_notices(certs: &[CertStatus]) -> (Vec<String>, bool) {
    let mut out = Vec::new();
    let mut urgent = false;
    for c in certs {
        match (c.days_left, &c.expires) {
            (Some(d), Ok(date)) if d < 0 => {
                urgent = true;
                out.push(format!(
                    "Certificate of the {} app registration ({}) expired on {date}: sign-in fails until it is renewed ({}, then upload the new one to Entra)",
                    c.app,
                    c.path.display(),
                    renew_command(&c.app)
                ));
            }
            (Some(d), Ok(date)) if d <= CERT_WARN_DAYS => {
                urgent |= d <= CERT_ATTENTION_DAYS;
                out.push(format!(
                    "Certificate of the {} app registration ({}) expires on {date}, in {d} days: renew it ({}) and upload the new one to Entra",
                    c.app,
                    c.path.display(),
                    renew_command(&c.app)
                ));
            }
            _ => {}
        }
    }
    (out, urgent)
}

// ------------------------------------------------------------------ summaries

/// A short, readable account of a run, for people at a terminal.
pub fn sync_summary(r: &Report) -> String {
    let mut s = String::new();
    let c = &r.counts;
    let mode = if r.mode == "apply" {
        "Sync"
    } else {
        "Test run (dry-run): nothing was sent"
    };
    let _ = writeln!(s, "{mode}, reference date {}", r.today);
    if c.rows_fetched > 0 || r.upload.is_some() {
        let _ = writeln!(s, "\nAFAS: {} rows", c.rows_fetched);
        let _ = writeln!(s, "  {:>6}  active", c.sent_active);
        let _ = writeln!(
            s,
            "  {:>6}  new hires, not started yet (disabled)",
            c.sent_inactive_prehire
        );
        let _ = writeln!(s, "  {:>6}  departed, disabled", c.sent_inactive_leaver);
        if c.sent_inactive_outside_window > 0 {
            let _ = writeln!(
                s,
                "  {:>6}  outside the date window but active last run: disabled once more",
                c.sent_inactive_outside_window
            );
        }
        let _ = writeln!(s, "  {:>6}  skipped (data errors)", c.excluded_errors);
        let _ = writeln!(
            s,
            "  {:>6}  not sent (outside the date window)",
            c.skipped_future_start + c.skipped_old_leaver
        );
        let _ = writeln!(
            s,
            "  {} to send in {} API calls; {} newly disabled",
            c.sent_total, c.api_calls_needed, c.new_disables
        );
    }
    list(
        &mut s,
        "Safety stops: nothing was uploaded",
        r.violations.iter().map(|v| v.message.clone()),
    );
    list(
        &mut s,
        "Skipped records (exclusions): ask HR to fix these in AFAS",
        r.exclusions.iter().map(|e| {
            format!(
                "{}  {}",
                e.employee_id.as_deref().unwrap_or("(no number)"),
                e.reason
            )
        }),
    );
    if r.missing.is_empty() {
        list(
            &mut s,
            "Missing from AFAS while active: not disabled, check them",
            r.disappeared_while_active.iter().cloned(),
        );
    } else {
        list(
            &mut s,
            "Missing from AFAS while active: not disabled, reported until handled (missing ack)",
            r.missing.iter().map(|m| {
                format!(
                    "{}  since {}{}",
                    m.employee_id,
                    m.since,
                    m.excluded_because
                        .as_deref()
                        .map(|e| format!(", skipped: {e}"))
                        .unwrap_or_default()
                )
            }),
        );
    }
    list(
        &mut s,
        "Sign-in names (UPN) that change",
        r.upn_changes
            .iter()
            .map(|u| format!("{}  {} → {}", u.employee_id, u.from, u.to)),
    );
    list(
        &mut s,
        "Managers who left or cannot be linked: ask HR to set a new manager",
        r.manager_gaps.iter().map(|g| {
            let cause = match g.cause {
                crate::plan::ManagerCause::Left => format!(
                    "left on {}",
                    g.date.map(|d| d.to_string()).unwrap_or_default()
                ),
                crate::plan::ManagerCause::NotInAfas => "not in AFAS".into(),
                crate::plan::ManagerCause::Skipped => "skipped (data error)".into(),
                crate::plan::ManagerCause::NotStarted => format!(
                    "starts on {}",
                    g.date.map(|d| d.to_string()).unwrap_or_default()
                ),
            };
            format!(
                "{}  {cause}; still manager of {}",
                g.manager_id,
                g.reports.join(", ")
            )
        }),
    );
    list(
        &mut s,
        "Warnings",
        r.warnings
            .iter()
            .map(|w| format!("{}  {}", w.employee_id, w.message)),
    );
    if let Some(u) = &r.upload {
        let _ = writeln!(
            s,
            "\nUpload: {} calls accepted by Microsoft ({} retries)",
            u.calls_accepted, u.retries
        );
    }
    if let Some(m) = &r.modules {
        let _ = writeln!(s, "\nModules:");
        if let Some(e) = &m.error {
            let _ = writeln!(s, "  could not start: {e}");
        }
        for (name, rep) in [
            ("Roles and licences", &m.roles),
            ("New hires (joiners)", &m.joiner),
            ("Departing employees (leavers)", &m.leaver),
            ("Webhook", &m.webhook),
        ] {
            let Some(x) = rep else { continue };
            let state = if let Some(e) = &x.error {
                format!("error: {e}")
            } else if let Some(v) = x.violations.first() {
                format!("stopped: {v}")
            } else {
                format!(
                    "{} planned, {} done, {} failed, {} notes",
                    x.planned.len(),
                    x.applied,
                    x.failed.len(),
                    x.notes.len()
                )
            };
            let _ = writeln!(s, "  {name}: {state}");
        }
    }
    list(&mut s, "Notices", r.notices.iter().cloned());
    list(
        &mut s,
        "Notifications",
        r.notifications.iter().map(|d| {
            format!(
                "{}: {}",
                d.channel,
                if d.ok {
                    d.detail.clone()
                } else {
                    format!("FAILED, {}", d.detail)
                }
            )
        }),
    );
    let _ = writeln!(s, "\nResult: {} (exit {})", r.result, r.exit_code);
    let ok = matches!(
        r.exit_code,
        crate::error::exit::OK | crate::error::exit::COMPLETED_WITH_EXCLUSIONS
    );
    if r.mode != "apply" && ok {
        let _ = writeln!(
            s,
            "Looks right? Run again with --apply to send it to Microsoft."
        );
    }
    let _ = writeln!(
        s,
        "All details: {} in the state directory (log: {}), or --json.",
        crate::state::report_file(r.mode == "apply"),
        crate::state::log_file(r.mode == "apply")
    );
    s
}

fn list(s: &mut String, title: &str, items: impl Iterator<Item = String>) {
    let items: Vec<String> = items.collect();
    if items.is_empty() {
        return;
    }
    let _ = writeln!(s, "\n{title} ({}):", items.len());
    for i in items.iter().take(10) {
        let _ = writeln!(s, "  {i}");
    }
    if items.len() > 10 {
        let _ = writeln!(s, "  … and {} more (see --json)", items.len() - 10);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_is_found_in_the_documented_order() {
        let none = |_: &Path| false;
        let installed = |p: &Path| p == Path::new(DEFAULT_CONFIG);
        assert_eq!(
            resolve_config(Some("x.toml".into()), Some("env.toml".into()), &installed),
            PathBuf::from("x.toml")
        );
        assert_eq!(
            resolve_config(None, Some("env.toml".into()), &installed),
            PathBuf::from("env.toml")
        );
        assert_eq!(
            resolve_config(None, Some("".into()), &installed),
            PathBuf::from(DEFAULT_CONFIG)
        );
        assert_eq!(
            resolve_config(None, None, &installed),
            PathBuf::from(DEFAULT_CONFIG)
        );
        assert_eq!(
            resolve_config(None, None, &none),
            PathBuf::from(LOCAL_CONFIG)
        );
    }

    #[test]
    fn root_is_refused_only_where_it_would_break_the_service() {
        let args = [
            "afas-entra-sync".to_string(),
            "sync".into(),
            "--apply".into(),
        ];
        let dir = Path::new("/var/lib/afas-entra-sync");
        let m = wrong_user(Some(0), dir, Some(998), Some("afas-sync"), &args).unwrap();
        assert!(
            m.contains("sudo -u afas-sync afas-entra-sync sync --apply"),
            "{m}"
        );
        // The service user itself, a root-owned directory, or no directory yet: fine.
        assert!(wrong_user(Some(998), dir, Some(998), Some("afas-sync"), &args).is_none());
        assert!(wrong_user(Some(0), dir, Some(0), Some("root"), &args).is_none());
        assert!(wrong_user(Some(0), dir, None, None, &args).is_none());
        // Arguments with spaces are quoted so the line can be pasted.
        let a2 = ["x".to_string(), "--reason".into(), "it's ok".into()];
        let m = wrong_user(Some(0), dir, Some(5), None, &a2).unwrap();
        assert!(m.contains("sudo -u 5 x --reason 'it'\\''s ok'"), "{m}");
    }

    fn report(mode: &'static str, exit_code: i32) -> Report {
        Report {
            mode,
            population: None,
            started_utc: String::new(),
            today: "2026-11-01".into(),
            counts: crate::plan::Counts {
                rows_fetched: 641,
                sent_active: 571,
                sent_total: 604,
                ..Default::default()
            },
            violations: vec![],
            exclusions: (0..12)
                .map(|i| crate::plan::Exclusion {
                    employee_id: Some(format!("{i:05}")),
                    reason: "invalid UPN".into(),
                })
                .collect(),
            warnings: vec![],
            disappeared_while_active: vec![],
            missing: vec![],
            upn_changes: vec![],
            manager_gaps: vec![],
            upload: None,
            modules: None,
            preview: None,
            notifications: vec![],
            log_file: None,
            notices: vec!["certificate expires".into()],
            result: "ok".into(),
            exit_code,
        }
    }

    #[test]
    fn summary_reads_like_a_report_and_only_suggests_apply_after_a_good_test_run() {
        let s = sync_summary(&report("dry-run", 3));
        assert!(s.starts_with("Test run (dry-run): nothing was sent"), "{s}");
        assert!(s.contains("641 rows") && s.contains("571  active"), "{s}");
        assert!(s.contains("Skipped records (exclusions): ask HR to fix these in AFAS (12):"));
        assert!(s.contains("00009  invalid UPN") && !s.contains("00010  invalid UPN"));
        assert!(s.contains("… and 2 more"));
        assert!(s.contains("Notices (1):"));
        assert!(s.contains("--apply"));
        for (mode, code) in [("dry-run", 30), ("dry-run", 20), ("apply", 0)] {
            assert!(
                !sync_summary(&report(mode, code)).contains("--apply"),
                "{mode} {code}"
            );
        }
        assert!(sync_summary(&report("apply", 0)).starts_with("Sync,"));
    }

    #[test]
    fn user_names_come_from_passwd() {
        let p = "root:x:0:0:root:/root:/bin/bash\nafas-sync:x:998:998::/nonexistent:/usr/sbin/nologin\n";
        assert_eq!(user_name(p, 998).as_deref(), Some("afas-sync"));
        assert_eq!(user_name(p, 0).as_deref(), Some("root"));
        assert_eq!(user_name(p, 5), None);
    }

    #[test]
    fn certificate_notices_at_their_boundaries() {
        let c = |days: i64| CertStatus {
            app: "roles".into(),
            path: "/etc/x.pem".into(),
            expires: Ok("2027-01-01".into()),
            days_left: Some(days),
        };
        assert_eq!(cert_notices(&[c(31)]), (vec![], false));
        let (n, urgent) = cert_notices(&[c(30)]);
        assert!(n[0].contains("in 30 days") && !urgent);
        assert!(!cert_notices(&[c(8)]).1);
        assert!(cert_notices(&[c(7)]).1);
        let (n, urgent) = cert_notices(&[c(-1)]);
        assert!(n[0].contains("expired") && urgent);
        // Unreadable certificates are for doctor, not for every run.
        let bad = CertStatus {
            expires: Err("cannot read".into()),
            days_left: None,
            ..c(0)
        };
        assert_eq!(cert_notices(&[bad]), (vec![], false));
    }
}
