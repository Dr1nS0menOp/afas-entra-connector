// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The afas-entra-sync Authors
//! Configuration (TOML). Unknown keys are rejected so a typo
//! never silently yields a default value.

use crate::error::{AppError, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub afas: AfasConfig,
    pub entra: EntraConfig,
    pub policy: PolicyConfig,
    #[serde(default)]
    pub upload: UploadConfig,
    pub state: StateConfig,
    /// Population (employees, contractors, interns …). One config per population.
    #[serde(default)]
    pub population: PopulationConfig,
    /// Admin GUI. OFF by default: can only be turned on in the base file.
    #[serde(default)]
    pub gui: GuiConfig,
    /// TLS policy for all outgoing connections (AFAS, Entra login, Graph).
    #[serde(default)]
    pub tls: TlsConfig,
    /// Optional modules (see `modules`). Each off unless present with `enabled = true`.
    #[serde(default)]
    pub roles: Option<crate::modules::settings::RolesConfig>,
    #[serde(default)]
    pub joiner: Option<crate::modules::settings::JoinerConfig>,
    #[serde(default)]
    pub leaver: Option<crate::modules::settings::LeaverConfig>,
    #[serde(default)]
    pub webhook: Option<crate::modules::settings::WebhookConfig>,
}

/// Lowest TLS version that is accepted.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum TlsVersion {
    #[serde(rename = "1.2")]
    V12,
    #[default]
    #[serde(rename = "1.3")]
    V13,
}

/// Post-quantum hybrid key exchange (X25519MLKEM768).
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PostQuantum {
    /// Offer it first; fall back to classical X25519/ECDHE if the server does not support it.
    #[default]
    Prefer,
    /// Only hybrid post-quantum groups: the connection fails if the server does not support them.
    Require,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// `"1.3"` (default) or `"1.2"`.
    #[serde(default)]
    pub min_version: TlsVersion,
    /// `"prefer"` (default) or `"require"`.
    #[serde(default)]
    pub post_quantum: PostQuantum,
}

#[derive(Debug, Clone, Default, Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GuiConfig {
    /// Master switch. `false` (default): `serve` does not start, and a running GUI stops.
    #[serde(default)]
    pub enabled: bool,
}

/// Settings that distinguish a population. Each population runs as its own
/// config with its own GetConnector, its own `state.dir` and preferably its own provisioning app.
#[derive(Debug, Clone, Default, Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PopulationConfig {
    /// Name in report and logs, e.g. "contractors".
    pub name: Option<String>,
    /// Prefix for the employee number, e.g. "CTR-", so numbers from
    /// different populations never match the same AD account.
    pub id_prefix: Option<String>,
    /// Fixed value for userType/employeeType, e.g. "Contractor".
    pub employee_type: Option<String>,
}

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct AfasConfig {
    /// E.g. `https://12345.rest.afas.online/ProfitRestServices`
    pub base_url: String,
    /// Name of the GetConnector.
    pub connector: String,
    /// Name of the environment variable holding the AFAS token (XML or only the data value).
    pub token_env: Option<String>,
    /// Or: path to a file containing the token.
    pub token_file: Option<PathBuf>,
    /// Rows per page (1..=10000).
    #[serde(default = "default_page_size")]
    pub page_size: u32,
    /// Field to sort on while paging; must be unique (employee number).
    pub order_by_field: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    #[serde(default = "default_afas_attempts")]
    pub max_attempts: u32,
    pub fields: FieldMap,
}

/// Mapping between our data model and the field names in the AFAS GetConnector.
#[derive(Debug, Clone, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct FieldMap {
    pub employee_id: String,
    pub given_name: String,
    pub name_prefix: Option<String>,
    pub family_name: String,
    pub display_name: Option<String>,
    pub upn: String,
    pub email: Option<String>,
    pub job_title: Option<String>,
    pub department: Option<String>,
    pub manager_id: Option<String>,
    pub cost_center: Option<String>,
    pub start_date: String,
    pub end_date: String,
    /// Extra attributes with an on/off toggle (`[afas.fields.extra]`).
    #[serde(default)]
    pub extra: ExtraFields,
    /// Filled from `[population]` on load; cannot be set directly.
    #[serde(skip)]
    pub population: PopulationConfig,
}

/// One optional attribute: only read and sent with `enabled = true`.
#[derive(Debug, Clone, Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Toggle {
    pub enabled: bool,
    pub field: String,
}

#[derive(Debug, Clone, Default, Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExtraFields {
    /// Work phone number → SCIM phoneNumbers[type=work].
    pub phone_work: Option<Toggle>,
    /// Mobile number → custom extension (`mobilePhone`); needs a mapping in the provisioning app.
    pub phone_mobile: Option<Toggle>,
    /// Office / work location → custom extension (`officeLocation`).
    pub office: Option<Toggle>,
    /// Employer / company → enterprise `organization`.
    pub company: Option<Toggle>,
    /// Employee type (Employee, Contractor, Intern …) → core `userType`.
    pub employee_type: Option<Toggle>,
    /// Job profile (code) → custom extension (`jobProfile`), for dynamic groups.
    pub job_profile: Option<Toggle>,
    /// Work address → SCIM addresses[type=work].
    pub street: Option<Toggle>,
    pub postal_code: Option<Toggle>,
    pub city: Option<Toggle>,
    /// Country code, 2 letters (ISO 3166), e.g. NL.
    pub country: Option<Toggle>,
    /// Send the hire date as a custom extension (`hireDate`).
    #[serde(default)]
    pub send_hire_date: bool,
    /// Send the leave date as a custom extension (`leaveDate`).
    #[serde(default)]
    pub send_leave_date: bool,
}

pub const OVERRIDES_FILE: &str = "overrides.toml";

/// Keys the GUI layer (`overrides.toml`) may never change: where secrets come
/// from, where tokens go, where the state lives, and the GUI switch itself.
/// Exception: `gui.enabled = false` is allowed (the GUI may turn itself off).
pub const LOCKED_KEYS: &[&str] = &[
    "afas.base_url",
    "afas.token_env",
    "afas.token_file",
    "entra.tenant_id",
    "entra.client_id",
    "entra.auth",
    "entra.client_secret_env",
    "entra.certificate_pem",
    "entra.private_key_pem",
    "entra.authority",
    "entra.graph_base",
    "state",
    "tls",
    // Modules: who they sign in as, which groups they may touch, where mail and events go.
    "roles.client_id",
    "roles.certificate_pem",
    "roles.private_key_pem",
    "roles.group_prefix",
    "joiner.client_id",
    "joiner.certificate_pem",
    "joiner.private_key_pem",
    "joiner.sender",
    "joiner.deliver_to",
    "joiner.fixed_address",
    "leaver.client_id",
    "leaver.certificate_pem",
    "leaver.private_key_pem",
    "webhook",
];

pub fn is_locked(path: &str) -> bool {
    LOCKED_KEYS
        .iter()
        .any(|k| path == *k || path.starts_with(&format!("{k}.")))
}

/// All leaf paths of a table, e.g. `policy.min_records`.
pub fn leaf_paths(t: &toml::Table, prefix: &str, out: &mut Vec<String>) {
    for (k, v) in t {
        let p = if prefix.is_empty() {
            k.clone()
        } else {
            format!("{prefix}.{k}")
        };
        match v {
            toml::Value::Table(sub) => leaf_paths(sub, &p, out),
            _ => out.push(p),
        }
    }
}

/// Checks that a GUI layer only contains allowed keys.
pub fn check_overrides(ov: &toml::Table) -> Result<()> {
    let mut paths = Vec::new();
    leaf_paths(ov, "", &mut paths);
    for p in paths {
        if p == "gui.enabled" {
            if ov.get("gui").and_then(|g| g.get("enabled")) != Some(&toml::Value::Boolean(false)) {
                return Err(AppError::Config(
                    "overrides.toml may only turn the GUI off, never on".into(),
                ));
            }
            continue;
        }
        if p.starts_with("gui.") || is_locked(&p) {
            return Err(AppError::Config(format!(
                "overrides.toml may not change '{p}' (config file only)"
            )));
        }
    }
    Ok(())
}

/// Deep merge: tables recursively, other values replaced.
pub fn merge(base: &mut toml::Table, top: &toml::Table) {
    for (k, v) in top {
        match (base.get_mut(k), v) {
            (Some(toml::Value::Table(b)), toml::Value::Table(t)) => merge(b, t),
            _ => {
                base.insert(k.clone(), v.clone());
            }
        }
    }
}

/// The layers of a loaded config, for the GUI.
pub struct Layers {
    pub base: toml::Table,
    pub overrides: toml::Table,
    pub merged: toml::Table,
    pub config: Config,
    /// `merged` plus every default the program fills in (for display in the GUI).
    pub effective: toml::Table,
}

/// Names of all toggles, in fixed order (also for the GUI).
pub const TOGGLE_NAMES: [&str; 10] = [
    "phone_work",
    "phone_mobile",
    "office",
    "company",
    "employee_type",
    "job_profile",
    "street",
    "postal_code",
    "city",
    "country",
];

impl ExtraFields {
    pub fn toggle(&self, name: &str) -> Option<&Option<Toggle>> {
        Some(match name {
            "phone_work" => &self.phone_work,
            "phone_mobile" => &self.phone_mobile,
            "office" => &self.office,
            "company" => &self.company,
            "employee_type" => &self.employee_type,
            "job_profile" => &self.job_profile,
            "street" => &self.street,
            "postal_code" => &self.postal_code,
            "city" => &self.city,
            "country" => &self.country,
            _ => return None,
        })
    }

    pub fn toggle_mut(&mut self, name: &str) -> Option<&mut Option<Toggle>> {
        Some(match name {
            "phone_work" => &mut self.phone_work,
            "phone_mobile" => &mut self.phone_mobile,
            "office" => &mut self.office,
            "company" => &mut self.company,
            "employee_type" => &mut self.employee_type,
            "job_profile" => &mut self.job_profile,
            "street" => &mut self.street,
            "postal_code" => &mut self.postal_code,
            "city" => &mut self.city,
            "country" => &mut self.country,
            _ => return None,
        })
    }

    /// Field name if the attribute is on.
    pub fn active(t: &Option<Toggle>) -> Option<&str> {
        t.as_ref().filter(|t| t.enabled).map(|t| t.field.as_str())
    }
}

impl FieldMap {
    /// All configured field names (required + optional).
    pub fn all_fields(&self) -> Vec<&str> {
        let mut v = vec![
            self.employee_id.as_str(),
            self.given_name.as_str(),
            self.family_name.as_str(),
            self.upn.as_str(),
            self.start_date.as_str(),
            self.end_date.as_str(),
        ];
        for o in [
            &self.name_prefix,
            &self.display_name,
            &self.email,
            &self.job_title,
            &self.department,
            &self.manager_id,
            &self.cost_center,
        ]
        .into_iter()
        .flatten()
        {
            v.push(o.as_str());
        }
        let x = &self.extra;
        for t in [
            &x.phone_work,
            &x.phone_mobile,
            &x.office,
            &x.company,
            &x.employee_type,
            &x.job_profile,
            &x.street,
            &x.postal_code,
            &x.city,
            &x.country,
        ] {
            if let Some(f) = ExtraFields::active(t) {
                v.push(f);
            }
        }
        v
    }
}

#[derive(Debug, Clone, Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthMode {
    Certificate,
    ClientSecret,
}

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct EntraConfig {
    pub tenant_id: String,
    pub client_id: String,
    pub auth: AuthMode,
    /// With `auth = "client_secret"`: name of the environment variable holding the secret.
    pub client_secret_env: Option<String>,
    /// With `auth = "certificate"`: PEM with the public certificate.
    pub certificate_pem: Option<PathBuf>,
    /// With `auth = "certificate"`: PEM with the private key (PKCS#8 or PKCS#1).
    pub private_key_pem: Option<PathBuf>,
    /// Object ID of the provisioning app's service principal.
    pub service_principal_id: String,
    /// Job ID of the provisioning job (e.g. `API2AD.xxxx.yyyy`).
    pub job_id: String,
    #[serde(default = "default_authority")]
    pub authority: String,
    #[serde(default = "default_graph_base")]
    pub graph_base: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    #[serde(default = "default_tz")]
    pub timezone: String,
    /// Allowed UPN domains (exact match, case-insensitive).
    pub allowed_upn_domains: Vec<String>,
    /// How many days before the start date the (disabled) account is created.
    pub prehire_days: u32,
    /// How many days after the end date we keep sending the record (as disabled).
    pub leaver_lookback_days: u32,
    /// Minimum number of records to send; fewer = stop.
    pub min_records: u32,
    /// Maximum drop (percent) compared with the last successful run; more = stop.
    pub max_drop_percent: u32,
    /// Maximum number of accounts going from active to disabled in one run.
    pub max_disables_per_run: u32,
    /// Maximum percentage of records with data errors; more = stop (points to a mapping error).
    pub max_invalid_percent: u32,
    /// Maximum API calls per run (protects the daily limit).
    pub max_calls_per_run: u32,
}

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct UploadConfig {
    /// Records per bulkUpload call (1..=50).
    #[serde(default = "default_batch")]
    pub batch_size: u32,
    /// Wait between calls. Microsoft limit: 40 calls per 5 s, so at least 125 ms.
    #[serde(default = "default_pace")]
    pub pace_ms: u64,
    #[serde(default = "default_upload_attempts")]
    pub max_attempts: u32,
    #[serde(default = "default_backoff")]
    pub backoff_base_ms: u64,
    #[serde(default = "default_backoff_max")]
    pub backoff_max_ms: u64,
    /// Wait on HTTP 500 "bucket full" (Microsoft advises 5 to 10 minutes).
    #[serde(default = "default_bucket_wait")]
    pub bucket_full_wait_secs: u64,
    /// Upper bound for a Retry-After header.
    #[serde(default = "default_retry_after_max")]
    pub max_retry_after_secs: u64,
}

impl Default for UploadConfig {
    fn default() -> Self {
        Self {
            batch_size: default_batch(),
            pace_ms: default_pace(),
            max_attempts: default_upload_attempts(),
            backoff_base_ms: default_backoff(),
            backoff_max_ms: default_backoff_max(),
            bucket_full_wait_secs: default_bucket_wait(),
            max_retry_after_secs: default_retry_after_max(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct StateConfig {
    /// Directory for state, lock and report.
    pub dir: PathBuf,
}

fn default_page_size() -> u32 {
    1000
}
fn default_timeout() -> u64 {
    120
}
fn default_afas_attempts() -> u32 {
    4
}
fn default_authority() -> String {
    "https://login.microsoftonline.com".into()
}
fn default_graph_base() -> String {
    "https://graph.microsoft.com/v1.0".into()
}
fn default_tz() -> String {
    "Europe/Amsterdam".into()
}
fn default_batch() -> u32 {
    50
}
fn default_pace() -> u64 {
    250
}
fn default_upload_attempts() -> u32 {
    6
}
fn default_backoff() -> u64 {
    2000
}
fn default_backoff_max() -> u64 {
    60_000
}
fn default_bucket_wait() -> u64 {
    300
}
fn default_retry_after_max() -> u64 {
    600
}

impl Config {
    /// Loads the config and then the GUI layer `<state.dir>/overrides.toml`.
    pub fn load(path: &Path) -> Result<Config> {
        Self::load_layers(path).map(|l| l.config)
    }

    pub fn load_layers(path: &Path) -> Result<Layers> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| AppError::Config(format!("cannot read {}: {e}", path.display())))?;
        let base_cfg = Self::parse(&text)?;
        let base: toml::Table = text
            .parse()
            .map_err(|e| AppError::Config(format!("invalid TOML: {e}")))?;
        let ov_path = base_cfg.state.dir.join(OVERRIDES_FILE);
        let overrides: toml::Table = match std::fs::read_to_string(&ov_path) {
            Ok(t) => t
                .parse()
                .map_err(|e| AppError::Config(format!("{} invalid: {e}", ov_path.display())))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => toml::Table::new(),
            Err(e) => {
                return Err(AppError::Config(format!(
                    "cannot read {}: {e}",
                    ov_path.display()
                )));
            }
        };
        Self::combine(base, overrides)
    }

    /// Merge base + GUI layer, check and validate.
    pub fn combine(base: toml::Table, overrides: toml::Table) -> Result<Layers> {
        check_overrides(&overrides)?;
        let mut merged = base.clone();
        merge(&mut merged, &overrides);
        let text = toml::to_string(&merged).map_err(|e| AppError::Internal(e.to_string()))?;
        let config = Self::parse(&text).map_err(|e| match e {
            AppError::Config(m) => AppError::Config(format!("after applying overrides.toml: {m}")),
            other => other,
        })?;
        let effective = toml::Table::try_from(&config)
            .map_err(|e| AppError::Internal(format!("effective config: {e}")))?;
        Ok(Layers {
            base,
            overrides,
            merged,
            config,
            effective,
        })
    }

    pub fn parse(text: &str) -> Result<Config> {
        let mut cfg: Config =
            toml::from_str(text).map_err(|e| AppError::Config(format!("invalid TOML: {e}")))?;
        cfg.validate()?;
        cfg.afas.fields.population = cfg.population.clone();
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        let err = |m: &str| Err(AppError::Config(m.to_string()));

        // AFAS
        if !self.afas.base_url.starts_with("https://") && !is_local_test_url(&self.afas.base_url) {
            return err("afas.base_url must start with https://");
        }
        if self.afas.connector.is_empty()
            || !self
                .afas
                .connector
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return err("afas.connector may only contain letters, digits, '_' and '-'");
        }
        match (&self.afas.token_env, &self.afas.token_file) {
            (Some(_), Some(_)) => {
                return err("use either afas.token_env or afas.token_file, not both");
            }
            (None, None) => return err("afas.token_env or afas.token_file is required"),
            _ => {}
        }
        if !(1..=10_000).contains(&self.afas.page_size) {
            return err("afas.page_size must be between 1 and 10000");
        }
        if self.afas.order_by_field.trim().is_empty() || self.afas.order_by_field.contains(',') {
            return err("afas.order_by_field must be one (unique) field, e.g. the employee number");
        }
        if self.afas.max_attempts == 0 || self.afas.timeout_secs == 0 {
            return err("afas.max_attempts and afas.timeout_secs must be > 0");
        }
        let fields = self.afas.fields.all_fields();
        let mut seen = std::collections::HashSet::new();
        for f in &fields {
            if f.trim().is_empty() {
                return err("afas.fields contains an empty field name");
            }
            if !seen.insert(*f) {
                return Err(AppError::Config(format!(
                    "afas.fields: field '{f}' is mapped to more than one attribute"
                )));
            }
        }

        // Entra
        if !is_guid(&self.entra.tenant_id) {
            return err("entra.tenant_id is not a GUID");
        }
        if !is_guid(&self.entra.client_id) {
            return err("entra.client_id is not a GUID");
        }
        if !is_guid(&self.entra.service_principal_id) {
            return err("entra.service_principal_id is not a GUID");
        }
        if self.entra.job_id.trim().is_empty()
            || !self
                .entra
                .job_id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        {
            return err("entra.job_id is empty or contains invalid characters");
        }
        match self.entra.auth {
            AuthMode::Certificate => {
                if self.entra.certificate_pem.is_none() || self.entra.private_key_pem.is_none() {
                    return err(
                        "auth = certificate requires entra.certificate_pem and entra.private_key_pem",
                    );
                }
                if self.entra.client_secret_env.is_some() {
                    return err("auth = certificate: remove entra.client_secret_env");
                }
            }
            AuthMode::ClientSecret => {
                if self.entra.client_secret_env.is_none() {
                    return err("auth = client_secret requires entra.client_secret_env");
                }
                if self.entra.certificate_pem.is_some() || self.entra.private_key_pem.is_some() {
                    return err("auth = client_secret: remove certificate_pem/private_key_pem");
                }
            }
        }
        for (name, url) in [
            ("entra.authority", &self.entra.authority),
            ("entra.graph_base", &self.entra.graph_base),
        ] {
            if !url.starts_with("https://") && !is_local_test_url(url) {
                return Err(AppError::Config(format!("{name} must start with https://")));
            }
        }
        if self.entra.timeout_secs == 0 {
            return err("entra.timeout_secs must be > 0");
        }

        // Population
        let pop = &self.population;
        if let Some(n) = &pop.name
            && (n.trim().is_empty() || n.len() > 32)
        {
            return err("population.name must be 1 to 32 characters");
        }
        if let Some(px) = &pop.id_prefix
            && (px.is_empty()
                || px.len() > 8
                || !px
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '-'))
        {
            return err("population.id_prefix: 1 to 8 characters, only A-Z, 0-9 and '-'");
        }
        if let Some(t) = &pop.employee_type {
            if t.trim().is_empty() || t.len() > 64 {
                return err("population.employee_type must be 1 to 64 characters");
            }
            if self
                .afas
                .fields
                .extra
                .employee_type
                .as_ref()
                .is_some_and(|t| t.enabled)
            {
                return err(
                    "use either population.employee_type or the extra attribute employee_type, not both",
                );
            }
        }

        // Policy
        if self.policy.timezone.parse::<chrono_tz::Tz>().is_err() {
            return err("policy.timezone is not a valid IANA time zone");
        }
        if self.policy.allowed_upn_domains.is_empty() {
            return err("policy.allowed_upn_domains cannot be empty");
        }
        for d in &self.policy.allowed_upn_domains {
            if d.is_empty()
                || d.contains('@')
                || !d.contains('.')
                || d.chars().any(char::is_whitespace)
            {
                return Err(AppError::Config(format!("invalid UPN domain: '{d}'")));
            }
        }
        if self.policy.prehire_days > 365 || self.policy.leaver_lookback_days > 365 {
            return err("prehire_days and leaver_lookback_days can be at most 365");
        }
        if self.policy.min_records == 0 {
            return err("policy.min_records must be at least 1");
        }
        if self.policy.max_drop_percent > 100 || self.policy.max_invalid_percent > 100 {
            return err("percentages must be between 0 and 100");
        }
        if self.policy.max_calls_per_run == 0 {
            return err("policy.max_calls_per_run must be > 0");
        }

        // Upload
        if !(1..=50).contains(&self.upload.batch_size) {
            return err("upload.batch_size must be between 1 and 50 (Microsoft limit)");
        }
        if self.upload.max_attempts == 0 {
            return err("upload.max_attempts must be > 0");
        }
        if self.upload.backoff_max_ms < self.upload.backoff_base_ms {
            return err("upload.backoff_max_ms must be >= backoff_base_ms");
        }
        crate::modules::settings::validate(
            self.roles.as_ref(),
            self.joiner.as_ref(),
            self.leaver.as_ref(),
            self.webhook.as_ref(),
        )
        .map_err(AppError::Config)?;
        // Departing employees are only in the upload for leaver_lookback_days after their
        // end date. A module that acts on them later would never see them again.
        let lookback = self.policy.leaver_lookback_days;
        if let Some(r) = self.roles.as_ref().filter(|r| r.enabled)
            && r.keep_leavers_days >= lookback
        {
            return err(&format!(
                "roles.keep_leavers_days ({}) must be smaller than policy.leaver_lookback_days ({lookback}): after that, departing employees are no longer in the upload and their groups would never be removed",
                r.keep_leavers_days
            ));
        }
        if self.leaver.as_ref().is_some_and(|l| l.enabled) && lookback == 0 {
            return err(
                "the leaver module needs policy.leaver_lookback_days of at least 1: with 0, departing employees are never in the upload",
            );
        }
        Ok(())
    }

    /// True if at least one module is switched on.
    pub fn any_module_enabled(&self) -> bool {
        self.roles.as_ref().is_some_and(|m| m.enabled)
            || self.joiner.as_ref().is_some_and(|m| m.enabled)
            || self.leaver.as_ref().is_some_and(|m| m.enabled)
            || self.webhook.as_ref().is_some_and(|m| m.enabled)
    }

    pub fn tz(&self) -> chrono_tz::Tz {
        // validated in validate()
        self.policy
            .timezone
            .parse()
            .unwrap_or(chrono_tz::Europe::Amsterdam)
    }
}

/// Tests only: http://127.0.0.1 and http://localhost are allowed.
fn is_local_test_url(u: &str) -> bool {
    u.starts_with("http://127.0.0.1:") || u.starts_with("http://localhost:")
}

pub fn is_guid(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 36 {
        return false;
    }
    b.iter().enumerate().all(|(i, c)| match i {
        8 | 13 | 18 | 23 => *c == b'-',
        _ => c.is_ascii_hexdigit(),
    })
}
