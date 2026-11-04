// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The afas-entra-sync Authors
//! `install` and `uninstall`: set up the tool on a Linux host without Ansible.
//!
//! Idempotent: running it again keeps the existing configuration, token and
//! certificate (unless asked to replace them) and only rewrites what it manages
//! (binary, systemd units). Every file it writes is validated first and written
//! atomically with restrictive permissions.
//!
//! All system access goes through [`System`], so the whole flow is testable
//! against a temporary directory with a fake system.

use crate::config::{Config, is_guid};
use crate::state::write_atomic;
use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

pub const SERVICE_USER: &str = "afas-sync";
pub const BIN: &str = "/usr/local/bin/afas-entra-sync";
pub const CFG_DIR: &str = "/etc/afas-entra-sync";
pub const STATE_DIR: &str = "/var/lib/afas-entra-sync";
pub const UNIT_DIR: &str = "/etc/systemd/system";
pub const DEFAULT_CONNECTOR: &str = "Entra_Medewerkers";

const EXAMPLE: &str = include_str!("../afas-entra-sync.example.toml");
const UNIT_SYNC: &str = "afas-entra-sync.service";
const TIMER_SYNC: &str = "afas-entra-sync.timer";
const UNIT_LOGS: &str = "afas-entra-sync-check-logs.service";
const TIMER_LOGS: &str = "afas-entra-sync-check-logs.timer";
const UNIT_GUI: &str = "afas-entra-sync-gui.service";
const ALL_UNITS: [&str; 5] = [UNIT_SYNC, TIMER_SYNC, UNIT_LOGS, TIMER_LOGS, UNIT_GUI];

/// Everything the installer needs from the operating system.
pub trait System {
    fn is_root(&self) -> bool;
    fn has_systemd(&self) -> bool;
    /// (uid, gid) of a user, if it exists.
    fn user_ids(&self, user: &str) -> Option<(u32, u32)>;
    fn run(&self, program: &str, args: &[&str]) -> Result<(), String>;
    fn chown(&self, path: &Path, uid: u32, gid: u32) -> Result<(), String>;
    fn interactive(&self) -> bool;
    /// One line of input; `secret` = do not echo.
    fn prompt(&self, question: &str, secret: bool) -> Result<String, String>;
    fn say(&self, line: &str);
}

/// The real system: commands, chown, a terminal.
pub struct RealSystem;

impl System for RealSystem {
    fn is_root(&self) -> bool {
        std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("Uid:"))
                    .and_then(|l| l.split_whitespace().nth(2).map(|e| e == "0"))
            })
            .unwrap_or(false)
    }
    fn has_systemd(&self) -> bool {
        Path::new("/run/systemd/system").is_dir()
    }
    fn user_ids(&self, user: &str) -> Option<(u32, u32)> {
        let id = |flag: &str| -> Option<u32> {
            let out = Command::new("id").args([flag, user]).output().ok()?;
            if !out.status.success() {
                return None;
            }
            String::from_utf8(out.stdout).ok()?.trim().parse().ok()
        };
        Some((id("-u")?, id("-g")?))
    }
    fn run(&self, program: &str, args: &[&str]) -> Result<(), String> {
        let out = Command::new(program)
            .args(args)
            .output()
            .map_err(|e| format!("cannot run {program}: {e}"))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(format!(
                "{program} {} failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            ))
        }
    }
    fn chown(&self, path: &Path, uid: u32, gid: u32) -> Result<(), String> {
        #[cfg(unix)]
        {
            std::os::unix::fs::chown(path, Some(uid), Some(gid))
                .map_err(|e| format!("chown {}: {e}", path.display()))
        }
        #[cfg(not(unix))]
        {
            let _ = (path, uid, gid);
            Err("install is only supported on Linux".into())
        }
    }
    fn interactive(&self) -> bool {
        std::io::stdin().is_terminal()
    }
    fn prompt(&self, question: &str, secret: bool) -> Result<String, String> {
        let _ = write!(std::io::stdout(), "{question} ");
        let _ = std::io::stdout().flush();
        let hide = secret
            && Command::new("stty")
                .arg("-echo")
                .status()
                .is_ok_and(|s| s.success());
        let mut line = String::new();
        let res = std::io::stdin().lock().read_line(&mut line);
        if hide {
            let _ = Command::new("stty").arg("echo").status();
            let _ = writeln!(std::io::stdout());
        }
        res.map_err(|e| format!("cannot read input: {e}"))?;
        Ok(line.trim().to_string())
    }
    fn say(&self, line: &str) {
        // A closed stdout (e.g. `| head`) must not abort an install halfway.
        let _ = writeln!(std::io::stdout(), "{line}");
    }
}

/// Answers that can be given as flags; missing ones are asked interactively.
#[derive(Debug, Default, Clone)]
pub struct Answers {
    pub afas_env: Option<String>,
    pub connector: Option<String>,
    pub tenant_id: Option<String>,
    pub client_id: Option<String>,
    pub service_principal_id: Option<String>,
    pub job_id: Option<String>,
    pub upn_domains: Vec<String>,
    pub employee_count: Option<u32>,
    /// The AFAS token itself (from `--token-file` or `AFAS_TOKEN`).
    pub token: Option<String>,
}

#[derive(Debug, Clone)]
pub struct InstallOptions {
    /// Filesystem root; `/` in production, a temporary directory in tests.
    pub root: PathBuf,
    /// The binary to install (normally the running executable).
    pub binary: PathBuf,
    pub answers: Answers,
    pub reconfigure: bool,
    pub replace_token: bool,
    pub renew_cert: bool,
    /// Enable and start the hourly sync and check-logs timers.
    pub enable_sync: bool,
    /// New configuration only: turn the admin GUI on.
    pub gui: bool,
}

#[derive(Debug, Clone)]
pub struct UninstallOptions {
    pub root: PathBuf,
    /// Also remove configuration, key, token, state and the service user.
    pub purge: bool,
    pub yes: bool,
}

fn p(root: &Path, abs: &str) -> PathBuf {
    root.join(abs.trim_start_matches('/'))
}

/// Result of `install`, for the summary and for tests.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    pub user_created: bool,
    pub binary_updated: bool,
    pub config_written: bool,
    pub token_written: bool,
    pub cert_created: bool,
    pub units_written: bool,
    pub sync_enabled: bool,
    pub cert_thumbprint: Option<String>,
}

pub fn install(sys: &dyn System, o: &InstallOptions) -> Result<Outcome, String> {
    if !sys.is_root() {
        return Err("run the installer as root (sudo)".into());
    }
    let mut out = Outcome::default();

    // 0. Ask and validate everything first, so a wrong answer leaves nothing half-done.
    let token_path = p(&o.root, &format!("{CFG_DIR}/afas.token"));
    let token = if token_path.exists() && !o.replace_token {
        None
    } else {
        let check = |t: &str| {
            crate::afas::auth_header(t)
                .map(|_| ())
                .map_err(|e| e.to_string())
        };
        let t = match &o.answers.token {
            Some(t) => {
                check(t)?;
                t.trim().to_string()
            }
            None => ask(sys, "AFAS token (input hidden):", true, None, check)?,
        };
        Some(t)
    };
    let cfg_path = p(&o.root, &format!("{CFG_DIR}/config.toml"));
    let config = if cfg_path.exists() && !o.reconfigure {
        let text = std::fs::read_to_string(&cfg_path).map_err(|e| e.to_string())?;
        Config::parse(&text).map_err(|e| format!("existing {CFG_DIR}/config.toml: {e}"))?;
        None
    } else {
        let a = complete_answers(sys, &o.answers)?;
        Some(build_config(&a, o.gui)?)
    };

    // 1. Service user.
    let (uid, gid) = match sys.user_ids(SERVICE_USER) {
        Some(ids) => {
            sys.say(&format!("ok      user {SERVICE_USER} exists"));
            ids
        }
        None => {
            sys.run(
                "useradd",
                &[
                    "--system",
                    "--no-create-home",
                    "--home-dir",
                    STATE_DIR,
                    "--shell",
                    "/usr/sbin/nologin",
                    SERVICE_USER,
                ],
            )?;
            out.user_created = true;
            sys.say(&format!("created user {SERVICE_USER}"));
            sys.user_ids(SERVICE_USER)
                .ok_or_else(|| format!("user {SERVICE_USER} not found after useradd"))?
        }
    };

    // 2. Directories, only for the service user.
    for d in [CFG_DIR, STATE_DIR] {
        let dir = p(&o.root, d);
        std::fs::create_dir_all(&dir).map_err(|e| format!("create {d}: {e}"))?;
        set_mode(&dir, 0o700)?;
        sys.chown(&dir, uid, gid)?;
    }
    sys.say(&format!(
        "ok      {CFG_DIR} and {STATE_DIR} (0700, {SERVICE_USER})"
    ));

    // 3. Binary.
    let bin = p(&o.root, BIN);
    let new =
        std::fs::read(&o.binary).map_err(|e| format!("cannot read {}: {e}", o.binary.display()))?;
    let same_file = std::fs::canonicalize(&o.binary).ok() == std::fs::canonicalize(&bin).ok();
    if same_file || std::fs::read(&bin).ok().as_deref() == Some(new.as_slice()) {
        sys.say(&format!("ok      {BIN} is up to date"));
    } else {
        if let Some(parent) = bin.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("create {}: {e}", parent.display()))?;
        }
        write_atomic(&bin, &new).map_err(|e| e.to_string())?;
        set_mode(&bin, 0o755)?;
        sys.chown(&bin, 0, 0)?;
        out.binary_updated = true;
        sys.say(&format!("updated {BIN}"));
    }

    // 4. AFAS token (collected and validated in step 0).
    match &token {
        None => sys.say(&format!("kept    {CFG_DIR}/afas.token")),
        Some(t) => {
            write_private(sys, &token_path, t.as_bytes(), 0o600, uid, gid)?;
            out.token_written = true;
            sys.say(&format!("written {CFG_DIR}/afas.token (0600)"));
        }
    }

    // 5. Configuration (built and validated in step 0).
    match &config {
        None => sys.say(&format!("kept    {CFG_DIR}/config.toml (valid)")),
        Some(text) => {
            if cfg_path.exists() {
                let backup = cfg_path.with_extension(format!(
                    "toml.bak-{}",
                    chrono::Utc::now().format("%Y%m%d%H%M%S")
                ));
                std::fs::copy(&cfg_path, &backup).map_err(|e| format!("backup: {e}"))?;
                sys.say(&format!("backup  {}", backup.display()));
            }
            write_private(sys, &cfg_path, text.as_bytes(), 0o600, uid, gid)?;
            out.config_written = true;
            sys.say(&format!("written {CFG_DIR}/config.toml (validated)"));
        }
    }

    // 6. Certificate for Entra.
    let key_path = p(&o.root, &format!("{CFG_DIR}/key.pem"));
    let cert_path = p(&o.root, &format!("{CFG_DIR}/cert.pem"));
    if key_path.exists() && cert_path.exists() && !o.renew_cert {
        set_mode(&key_path, 0o600)?;
        sys.chown(&key_path, uid, gid)?;
        sys.say(&format!("kept    {CFG_DIR}/cert.pem and key.pem"));
    } else {
        for f in [&key_path, &cert_path] {
            if f.exists() {
                std::fs::rename(f, f.with_extension("pem.old"))
                    .map_err(|e| format!("keep old {}: {e}", f.display()))?;
            }
        }
        let (cert_pem, key_pem) = new_certificate()?;
        write_private(sys, &key_path, key_pem.as_bytes(), 0o600, uid, gid)?;
        write_private(sys, &cert_path, cert_pem.as_bytes(), 0o644, uid, gid)?;
        out.cert_created = true;
        sys.say(&format!(
            "created {CFG_DIR}/cert.pem and key.pem (RSA 3072, valid 365 days)"
        ));
    }
    out.cert_thumbprint = Some(thumbprint(
        &std::fs::read(&cert_path).map_err(|e| e.to_string())?,
    )?);

    // 7. systemd units.
    let gui_on = Config::parse(&std::fs::read_to_string(&cfg_path).map_err(|e| e.to_string())?)
        .map(|c| c.gui.enabled)
        .unwrap_or(false);
    if sys.has_systemd() {
        let units = p(&o.root, UNIT_DIR);
        std::fs::create_dir_all(&units).map_err(|e| format!("create {UNIT_DIR}: {e}"))?;
        for (name, body) in unit_files(gui_on) {
            let path = units.join(name);
            write_atomic(&path, body.as_bytes()).map_err(|e| e.to_string())?;
            set_mode(&path, 0o644)?;
        }
        if !gui_on {
            let _ = std::fs::remove_file(units.join(UNIT_GUI));
        }
        out.units_written = true;
        sys.run("systemctl", &["daemon-reload"])?;
        sys.say(&format!("written systemd units in {UNIT_DIR}"));
        if o.enable_sync {
            sys.run("systemctl", &["enable", "--now", TIMER_SYNC, TIMER_LOGS])?;
            out.sync_enabled = true;
            sys.say("enabled hourly sync (:07) and check-logs (:22) timers");
        }
        if gui_on {
            sys.run("systemctl", &["enable", UNIT_GUI])?;
            sys.run("systemctl", &["restart", UNIT_GUI])?;
            sys.say("started admin GUI on 127.0.0.1:8080");
        } else {
            let _ = sys.run("systemctl", &["disable", "--now", UNIT_GUI]);
        }
    } else {
        sys.say("note    no systemd found: schedule `afas-entra-sync -c /etc/afas-entra-sync/config.toml sync --apply` yourself");
    }

    summary(sys, &out, o);
    Ok(out)
}

fn summary(sys: &dyn System, out: &Outcome, o: &InstallOptions) {
    let tp = out.cert_thumbprint.as_deref().unwrap_or("?");
    sys.say("");
    sys.say("Next steps:");
    sys.say(&format!(
        "  1. Upload {CFG_DIR}/cert.pem to the app registration in Entra (Certificates & secrets).\n     Thumbprint shown by Entra: {tp}"
    ));
    sys.say("  2. Check everything:            sudo -u afas-sync afas-entra-sync doctor");
    sys.say("  3. Dry-run (sends nothing):     sudo -u afas-sync afas-entra-sync sync");
    if !o.enable_sync {
        sys.say("  4. Go live (hourly sync):       sudo afas-entra-sync install --enable-sync");
    }
}

fn set_mode(path: &Path, mode: u32) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .map_err(|e| format!("chmod {}: {e}", path.display()))
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
        Ok(())
    }
}

fn write_private(
    sys: &dyn System,
    path: &Path,
    data: &[u8],
    mode: u32,
    uid: u32,
    gid: u32,
) -> Result<(), String> {
    write_atomic(path, data).map_err(|e| e.to_string())?;
    set_mode(path, mode)?;
    sys.chown(path, uid, gid)
}

/// Asks until the answer passes `check` (at most 5 times).
fn ask(
    sys: &dyn System,
    question: &str,
    secret: bool,
    default: Option<&str>,
    check: impl Fn(&str) -> Result<(), String>,
) -> Result<String, String> {
    if !sys.interactive() {
        // Unattended: a question with a default takes the default; one without fails.
        return match default {
            Some(d) => check(d).map(|()| d.to_string()),
            None => Err(format!(
                "missing value: {question} (no terminal; pass it as a flag)"
            )),
        };
    }
    let q = match default {
        Some(d) => format!("{question} [{d}]"),
        None => question.to_string(),
    };
    for _ in 0..5 {
        let mut v = sys.prompt(&q, secret)?;
        if v.is_empty()
            && let Some(d) = default
        {
            v = d.to_string();
        }
        match check(&v) {
            Ok(()) => return Ok(v),
            Err(e) => sys.say(&format!("  {e}")),
        }
    }
    Err(format!("no valid answer for: {question}"))
}

fn check_env(v: &str) -> Result<(), String> {
    if (1..=10).contains(&v.len()) && v.chars().all(|c| c.is_ascii_digit()) {
        return Ok(());
    }
    if v.starts_with("https://") && !v.contains(char::is_whitespace) {
        return Ok(());
    }
    Err("enter the environment number (e.g. 12345) or the full https:// REST address".into())
}

fn check_connector(v: &str) -> Result<(), String> {
    if !v.is_empty()
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        Ok(())
    } else {
        Err("letters, digits, '_' and '-' only".into())
    }
}

fn check_guid(v: &str) -> Result<(), String> {
    if is_guid(v) {
        Ok(())
    } else {
        Err("not a GUID (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)".into())
    }
}

fn check_job(v: &str) -> Result<(), String> {
    if !v.is_empty()
        && v.len() <= 256
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || ".-_".contains(c))
    {
        Ok(())
    } else {
        Err("copy the job ID from the endpoint URL (e.g. API2AD.xxxx.yyyy)".into())
    }
}

fn split_domains(v: &str) -> Vec<String> {
    v.split(',')
        .map(|d| d.trim().to_ascii_lowercase())
        .filter(|d| !d.is_empty())
        .collect()
}

fn check_domains(v: &str) -> Result<(), String> {
    let ds = split_domains(v);
    let ok = !ds.is_empty()
        && ds.iter().all(|d| {
            d.contains('.')
                && !d.starts_with('.')
                && !d.ends_with('.')
                && d.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        });
    if ok {
        Ok(())
    } else {
        Err("one or more domains, comma-separated (e.g. example.com)".into())
    }
}

fn check_count(v: &str) -> Result<(), String> {
    match v.parse::<u32>() {
        Ok(n) if (1..=10_000_000).contains(&n) => Ok(()),
        _ => Err("a whole number above 0".into()),
    }
}

/// Fills in missing answers by asking; validates the ones given as flags.
pub fn complete_answers(sys: &dyn System, given: &Answers) -> Result<Answers, String> {
    let mut a = given.clone();
    let get = |cur: &Option<String>,
               q: &str,
               default: Option<&str>,
               check: fn(&str) -> Result<(), String>|
     -> Result<String, String> {
        match cur {
            Some(v) => check(v).map(|()| v.clone()).map_err(|e| format!("{q} {e}")),
            None => ask(sys, q, false, default, check),
        }
    };
    a.afas_env = Some(get(
        &a.afas_env,
        "AFAS environment number (from https://<nr>.rest.afas.online):",
        None,
        check_env,
    )?);
    a.connector = Some(get(
        &a.connector,
        "AFAS GetConnector name:",
        Some(DEFAULT_CONNECTOR),
        check_connector,
    )?);
    a.tenant_id = Some(get(&a.tenant_id, "Entra tenant ID:", None, check_guid)?);
    a.client_id = Some(get(
        &a.client_id,
        "Application (client) ID of the app registration:",
        None,
        check_guid,
    )?);
    a.service_principal_id = Some(get(
        &a.service_principal_id,
        "Service principal object ID of the provisioning app:",
        None,
        check_guid,
    )?);
    a.job_id = Some(get(
        &a.job_id,
        "Provisioning job ID (API2AD.…):",
        None,
        check_job,
    )?);
    if a.upn_domains.is_empty() {
        let v = ask(
            sys,
            "Allowed UPN domain(s), comma-separated:",
            false,
            None,
            check_domains,
        )?;
        a.upn_domains = split_domains(&v);
    } else {
        check_domains(&a.upn_domains.join(","))?;
        a.upn_domains = split_domains(&a.upn_domains.join(","));
    }
    if a.employee_count.is_none() {
        let v = ask(
            sys,
            "Current number of employees in the GetConnector:",
            false,
            None,
            check_count,
        )?;
        a.employee_count = v.parse().ok();
    }
    Ok(a)
}

/// The example configuration with the answers filled in, comments kept, and validated.
pub fn build_config(a: &Answers, gui: bool) -> Result<String, String> {
    use toml_edit::{Array, DocumentMut, value};
    let mut doc: DocumentMut = EXAMPLE
        .parse()
        .map_err(|e| format!("example config: {e}"))?;
    let env = a.afas_env.as_deref().ok_or("AFAS environment missing")?;
    let base = if env.starts_with("https://") {
        env.trim_end_matches('/').to_string()
    } else {
        format!("https://{env}.rest.afas.online/ProfitRestServices")
    };
    doc["afas"]["base_url"] = value(base);
    doc["afas"]["connector"] = value(a.connector.as_deref().unwrap_or(DEFAULT_CONNECTOR));
    if let Some(t) = doc["afas"].as_table_mut() {
        t.remove("token_env");
    }
    doc["afas"]["token_file"] = value(format!("{CFG_DIR}/afas.token"));
    doc["entra"]["tenant_id"] = value(a.tenant_id.as_deref().ok_or("tenant ID missing")?);
    doc["entra"]["client_id"] = value(a.client_id.as_deref().ok_or("client ID missing")?);
    doc["entra"]["auth"] = value("certificate");
    doc["entra"]["certificate_pem"] = value(format!("{CFG_DIR}/cert.pem"));
    doc["entra"]["private_key_pem"] = value(format!("{CFG_DIR}/key.pem"));
    doc["entra"]["service_principal_id"] = value(
        a.service_principal_id
            .as_deref()
            .ok_or("service principal ID missing")?,
    );
    doc["entra"]["job_id"] = value(a.job_id.as_deref().ok_or("job ID missing")?);
    let mut domains = Array::new();
    for d in &a.upn_domains {
        domains.push(d.as_str());
    }
    doc["policy"]["allowed_upn_domains"] = value(domains);
    if let Some(n) = a.employee_count {
        // 90% of today's number: a larger drop stops the run (exit 20).
        doc["policy"]["min_records"] = value(i64::from((n * 9 / 10).max(1)));
    }
    doc["state"]["dir"] = value(STATE_DIR);
    doc["gui"]["enabled"] = value(gui);
    let text = format!(
        "# Written by `afas-entra-sync install` on {}. Edit freely; run check-config after changes.\n{}",
        chrono::Utc::now().format("%Y-%m-%d"),
        doc
    );
    Config::parse(&text).map_err(|e| format!("generated configuration is invalid: {e}"))?;
    Ok(text)
}

/// A module with its own app registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupModule {
    Roles,
    Joiner,
    Leaver,
    /// Email notifications (Graph sendMail).
    Notify,
    /// Read-only look-up for the test-run preview.
    Preview,
}

impl SetupModule {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "roles" => Ok(Self::Roles),
            "joiner" | "new-hires" => Ok(Self::Joiner),
            "leaver" | "departing" => Ok(Self::Leaver),
            "notify" | "notifications" => Ok(Self::Notify),
            "preview" => Ok(Self::Preview),
            _ => Err(format!(
                "unknown module {s:?}: use roles, joiner, leaver, notify or preview"
            )),
        }
    }
    /// Config section and file prefix.
    pub fn key(self) -> &'static str {
        match self {
            Self::Roles => "roles",
            Self::Joiner => "joiner",
            Self::Leaver => "leaver",
            Self::Notify => "notify",
            Self::Preview => "preview",
        }
    }
    pub fn title(self) -> &'static str {
        match self {
            Self::Roles => "Roles and licences",
            Self::Joiner => "New hires (joiner)",
            Self::Leaver => "Departing employees (leaver)",
            Self::Notify => "Notifications by email",
            Self::Preview => "Test-run preview (read-only look-up in Entra)",
        }
    }
    /// Microsoft Graph application permissions granted in Entra.
    pub fn permissions(self) -> &'static [&'static str] {
        match self {
            Self::Roles => &["GroupMember.ReadWrite.All", "User.Read.All"],
            Self::Joiner => &["UserAuthMethod-TAP.ReadWrite.All", "User.Read.All"],
            Self::Leaver => &[
                "User.RevokeSessions.All",
                "User.Read.All",
                "MailboxSettings.ReadWrite",
            ],
            Self::Notify => &[],
            Self::Preview => &["User.Read.All"],
        }
    }
}

#[derive(Debug, Clone)]
pub struct ModuleSetupOptions {
    pub root: PathBuf,
    pub module: SetupModule,
    /// Replace an existing certificate (the old one is kept as *.pem.old).
    pub renew: bool,
}

/// Creates the module's certificate and key (owned by the service user, key 0600) and
/// prints what to do in Entra, with the config section to add. Returns the thumbprint.
pub fn module_setup(sys: &dyn System, o: &ModuleSetupOptions) -> Result<String, String> {
    if !sys.is_root() {
        return Err("run module-setup as root (sudo)".into());
    }
    let (uid, gid) = sys.user_ids(SERVICE_USER).ok_or_else(|| {
        format!("user {SERVICE_USER} does not exist: run `sudo afas-entra-sync install` first")
    })?;
    let dir = p(&o.root, CFG_DIR);
    if !dir.is_dir() {
        return Err(format!(
            "{CFG_DIR} does not exist: run `sudo afas-entra-sync install` first"
        ));
    }
    let m = o.module.key();
    let cert_abs = format!("{CFG_DIR}/{m}-cert.pem");
    let key_abs = format!("{CFG_DIR}/{m}-key.pem");
    let (cert_path, key_path) = (p(&o.root, &cert_abs), p(&o.root, &key_abs));
    let created = if cert_path.exists() && key_path.exists() && !o.renew {
        set_mode(&key_path, 0o600)?;
        sys.chown(&key_path, uid, gid)?;
        sys.say(&format!(
            "kept    {cert_abs} and {m}-key.pem (use --renew for a new one)"
        ));
        false
    } else {
        for f in [&key_path, &cert_path] {
            if f.exists() {
                std::fs::rename(f, f.with_extension("pem.old"))
                    .map_err(|e| format!("keep old {}: {e}", f.display()))?;
            }
        }
        let (cert_pem, key_pem) = new_certificate_named(&format!("afas-entra-sync-{m}"))?;
        write_private(sys, &key_path, key_pem.as_bytes(), 0o600, uid, gid)?;
        write_private(sys, &cert_path, cert_pem.as_bytes(), 0o644, uid, gid)?;
        sys.say(&format!(
            "created {cert_abs} and {m}-key.pem (RSA 3072, valid 365 days)"
        ));
        true
    };
    let tp = thumbprint(&std::fs::read(&cert_path).map_err(|e| e.to_string())?)?;

    let perms = o.module.permissions().join(", ");
    sys.say("");
    sys.say(&format!("Next steps for {}:", o.module.title()));
    if created && o.renew {
        sys.say(&format!(
            "  1. Upload the new {cert_abs} to the module's existing app registration\n     (Certificates & secrets). Thumbprint: {tp}\n     Delete the old certificate there once a run has worked."
        ));
        return Ok(tp);
    }
    sys.say(&format!(
        "  1. Entra admin center: App registrations > New registration\n     Name: afas-entra-sync-{m}; single tenant; no redirect URI."
    ));
    sys.say(&format!(
        "  2. Certificates & secrets > Certificates > Upload: {cert_abs}\n     Thumbprint shown by Entra: {tp}. Do not create a client secret."
    ));
    if perms.is_empty() {
        sys.say("  3. API permissions: add none in Entra (remove the default User.Read).");
    } else {
        sys.say(&format!(
            "  3. API permissions > Add > Microsoft Graph > Application permissions:\n     {perms}\n     then Grant admin consent."
        ));
    }
    let mut n = 4;
    match o.module {
        SetupModule::Joiner => {
            sys.say("  4. Mail.Send: do NOT grant it in Entra. Grant it with Exchange RBAC for Applications,\n     scoped to the sender mailbox (PowerShell in docs/MODULES.md). Turn on the\n     Temporary Access Pass method under Authentication methods > Policies.");
            n += 1;
        }
        SetupModule::Notify => {
            sys.say("  4. Mail.Send: do NOT grant it in Entra. Grant it with Exchange RBAC for Applications,\n     scoped to the sender mailbox only (PowerShell in docs/MODULES.md, Notifications).");
            n += 1;
        }
        _ => {}
    }
    sys.say(&format!(
        "  {n}. Add this to {CFG_DIR}/config.toml (client_id = the Application (client) ID):\n"
    ));
    let section = match o.module {
        SetupModule::Roles => format!(
            "[roles]\nenabled = true\nclient_id = \"<application id>\"\ncertificate_pem = \"{cert_abs}\"\nprivate_key_pem = \"{key_abs}\"\ngroup_prefix = \"AFAS-\"\n\n[[roles.rule]]\ngroup_id = \"<object id of a cloud security group>\"\nall = true\n"
        ),
        SetupModule::Joiner => format!(
            "[joiner]\nenabled = true\nclient_id = \"<application id>\"\ncertificate_pem = \"{cert_abs}\"\nprivate_key_pem = \"{key_abs}\"\nsender = \"<mailbox that sends the code>\"\ndeliver_to = \"manager\"\nfixed_address = \"<service desk address>\"\n"
        ),
        SetupModule::Leaver => format!(
            "[leaver]\nenabled = true\nclient_id = \"<application id>\"\ncertificate_pem = \"{cert_abs}\"\nprivate_key_pem = \"{key_abs}\"\n# auto_reply = \"{{display_name}} no longer works here. Please contact {{manager_name}} ({{manager_email}}).\"\n"
        ),
        SetupModule::Notify => format!(
            "[notify]\non = [\"failure\", \"attention\", \"recovered\"]\n\n[notify.email]\nclient_id = \"<application id>\"\ncertificate_pem = \"{cert_abs}\"\nprivate_key_pem = \"{key_abs}\"\nsender = \"<mailbox that sends the reports>\"\n\n[[notify.channel]]\nkind = \"email\"\nname = \"identity-team\"\nto = [\"<team mailbox>\"]\n"
        ),
        SetupModule::Preview => format!(
            "[preview]\nclient_id = \"<application id>\"\ncertificate_pem = \"{cert_abs}\"\nprivate_key_pem = \"{key_abs}\"\n# new_accounts_ou = \"OU=New hires,OU=Staff,DC=example,DC=com\"\n"
        ),
    };
    sys.say(&section);
    sys.say(&format!(
        "  {}. Check it: sudo -u {SERVICE_USER} afas-entra-sync doctor\n     then a test run: sudo -u {SERVICE_USER} afas-entra-sync sync",
        n + 1
    ));
    Ok(tp)
}

/// Self-signed RSA 3072 / SHA-256 certificate for Entra, valid 365 days.
pub fn new_certificate() -> Result<(String, String), String> {
    new_certificate_named("afas-entra-sync")
}

/// Self-signed RSA 3072 / SHA-256 certificate with this common name, valid 365 days.
pub fn new_certificate_named(common_name: &str) -> Result<(String, String), String> {
    use chrono::Datelike;
    let key = rcgen::KeyPair::generate_rsa_for(&rcgen::PKCS_RSA_SHA256, rcgen::RsaKeySize::_3072)
        .map_err(|e| format!("key generation failed: {e}"))?;
    let mut params = rcgen::CertificateParams::default();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, common_name);
    let today = chrono::Utc::now().date_naive();
    let end = today + chrono::Days::new(365);
    params.not_before = rcgen::date_time_ymd(today.year(), today.month() as u8, today.day() as u8);
    params.not_after = rcgen::date_time_ymd(end.year(), end.month() as u8, end.day() as u8);
    let cert = params
        .self_signed(&key)
        .map_err(|e| format!("certificate creation failed: {e}"))?;
    Ok((cert.pem(), key.serialize_pem()))
}

/// SHA-1 thumbprint as Entra shows it (uppercase hex).
pub fn thumbprint(cert_pem: &[u8]) -> Result<String, String> {
    use sha1::Digest;
    let block = pem::parse(cert_pem).map_err(|e| format!("cert.pem: {e}"))?;
    Ok(sha1::Sha1::digest(block.contents())
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect())
}

const HARDENING: &str = "UMask=0077
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/afas-entra-sync
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
ProtectProc=invisible
ProcSubset=pid
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
CapabilityBoundingSet=
AmbientCapabilities=
SystemCallArchitectures=native
SystemCallFilter=@system-service
";

pub fn unit_files(gui: bool) -> Vec<(&'static str, String)> {
    let head = "# Managed by `afas-entra-sync install`; rewritten on every install.\n";
    let oneshot = |desc: &str, args: &str| {
        format!(
            "{head}[Unit]\nDescription={desc}\nWants=network-online.target\nAfter=network-online.target\n\n[Service]\nType=oneshot\nUser={SERVICE_USER}\nGroup={SERVICE_USER}\nExecStart={BIN} -c {CFG_DIR}/config.toml {args}\n{HARDENING}"
        )
    };
    let timer = |desc: &str, minute: u8, unit: &str| {
        format!(
            "{head}[Unit]\nDescription={desc}\n\n[Timer]\nOnCalendar=*-*-* *:{minute:02}:00\nPersistent=true\nUnit={unit}\n\n[Install]\nWantedBy=timers.target\n"
        )
    };
    let mut v = vec![
        (
            UNIT_SYNC,
            oneshot("AFAS to Entra provisioning", "sync --apply"),
        ),
        (
            TIMER_SYNC,
            timer("AFAS to Entra provisioning, hourly", 7, UNIT_SYNC),
        ),
        (
            UNIT_LOGS,
            oneshot(
                "AFAS to Entra provisioning log check",
                "check-logs --since-minutes 60",
            ),
        ),
        (
            TIMER_LOGS,
            timer(
                "AFAS to Entra provisioning log check, hourly",
                22,
                UNIT_LOGS,
            ),
        ),
    ];
    if gui {
        v.push((
            UNIT_GUI,
            format!(
                "{head}[Unit]\nDescription=afas-entra-sync admin GUI\nWants=network-online.target\nAfter=network-online.target\n\n[Service]\nType=simple\nUser={SERVICE_USER}\nGroup={SERVICE_USER}\nExecStart={BIN} -c {CFG_DIR}/config.toml serve --listen 127.0.0.1:8080\nRestart=on-failure\nRestartSec=10\n{HARDENING}\n[Install]\nWantedBy=multi-user.target\n"
            ),
        ));
    }
    v
}

pub fn uninstall(sys: &dyn System, o: &UninstallOptions) -> Result<(), String> {
    if !sys.is_root() {
        return Err("run the uninstaller as root (sudo)".into());
    }
    if o.purge && !o.yes {
        let answer = ask(
            sys,
            "This deletes the configuration, AFAS token, private key and state. Type PURGE to continue:",
            false,
            None,
            |v| {
                if v == "PURGE" {
                    Ok(())
                } else {
                    Err("type PURGE, or press Ctrl+C".into())
                }
            },
        )?;
        debug_assert_eq!(answer, "PURGE");
    }
    if sys.has_systemd() {
        let _ = sys.run(
            "systemctl",
            &["disable", "--now", TIMER_SYNC, TIMER_LOGS, UNIT_GUI],
        );
        for u in ALL_UNITS {
            let _ = std::fs::remove_file(p(&o.root, &format!("{UNIT_DIR}/{u}")));
        }
        sys.run("systemctl", &["daemon-reload"])?;
        sys.say("removed systemd units");
    }
    remove_if_exists(&p(&o.root, BIN))?;
    sys.say(&format!("removed {BIN}"));
    if o.purge {
        for d in [CFG_DIR, STATE_DIR] {
            let dir = p(&o.root, d);
            if dir.exists() {
                std::fs::remove_dir_all(&dir).map_err(|e| format!("remove {d}: {e}"))?;
            }
            sys.say(&format!("removed {d}"));
        }
        if sys.user_ids(SERVICE_USER).is_some() {
            sys.run("userdel", &[SERVICE_USER])?;
            sys.say(&format!("removed user {SERVICE_USER}"));
        }
    } else {
        sys.say(&format!(
            "kept    {CFG_DIR} and {STATE_DIR} (use --purge to remove them; remember the app registration in Entra)"
        ));
    }
    Ok(())
}

fn remove_if_exists(path: &Path) -> Result<(), String> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("remove {}: {e}", path.display())),
    }
}
