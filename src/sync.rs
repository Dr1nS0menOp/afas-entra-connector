// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The afas-entra-sync Authors
//! The full run: lock → AFAS → plan → checks → (upload) → state.

use crate::afas;
use crate::config::Config;
use crate::entra::{self, Credential, TokenProvider, UploadOutcome};
use crate::error::{AppError, Result, exit};
use crate::http::build_client;
use crate::model::check_schema;
use crate::plan::{Counts, Exclusion, GuardViolation, Plan, PlanInput, Warning, build_plan};
use crate::scim::bulk_requests;
use crate::state::{RecordState, STATE_VERSION, State, StateStore, write_atomic};
use chrono::NaiveDate;
use serde::Serialize;
use std::path::PathBuf;
use std::time::Duration;

pub struct RunOptions {
    /// Without `apply` nothing is sent to Entra.
    pub apply: bool,
    /// Dry-run only: pretend it is this date.
    pub as_of: Option<NaiveDate>,
    pub allow_mass_disable: bool,
    /// Writes the SCIM payloads to this file (contains personal data).
    pub dump_payload: Option<PathBuf>,
    /// For tests against a local mock: do not use the system proxy.
    pub use_system_proxy: bool,
    /// Who started the run (access log): "cli", "timer", or the GUI user.
    pub actor: String,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub mode: &'static str,
    /// Name from `[population]`, so reports can be told apart per population.
    pub population: Option<String>,
    pub started_utc: String,
    pub today: String,
    pub counts: Counts,
    pub violations: Vec<GuardViolation>,
    pub exclusions: Vec<Exclusion>,
    pub warnings: Vec<Warning>,
    /// Active last run, no longer sent: review manually.
    pub disappeared_while_active: Vec<String>,
    pub upload: Option<UploadOutcome>,
    /// Results of the optional modules (roles, joiner, leaver, webhook).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modules: Option<crate::modules::ModulesReport>,
    pub result: String,
    pub exit_code: i32,
}

#[derive(Debug)]
pub struct RunResult {
    pub report: Report,
    pub plan: Option<Plan>,
}

pub fn run(
    cfg: &Config,
    opts: &RunOptions,
    sleep: &dyn Fn(Duration),
) -> std::result::Result<RunResult, (AppError, Option<Box<Report>>)> {
    if opts.apply && opts.as_of.is_some() {
        return Err((
            AppError::Config("--as-of cannot be combined with --apply".into()),
            None,
        ));
    }
    let store = StateStore::new(&cfg.state.dir).map_err(|e| (e, None))?;
    let _lock = store.lock().map_err(|e| (e, None))?;
    let started = chrono::Utc::now();
    let today = opts
        .as_of
        .unwrap_or_else(|| started.with_timezone(&cfg.tz()).date_naive());

    let mut report = Report {
        mode: if opts.apply { "apply" } else { "dry-run" },
        population: cfg.population.name.clone(),
        started_utc: started.to_rfc3339(),
        today: today.to_string(),
        counts: Counts::default(),
        violations: vec![],
        exclusions: vec![],
        warnings: vec![],
        disappeared_while_active: vec![],
        upload: None,
        modules: None,
        result: String::new(),
        exit_code: exit::OK,
    };

    let result = run_inner(cfg, opts, sleep, &store, today, &mut report);
    let (res, plan) = match result {
        Ok(plan) => {
            if cfg.any_module_enabled() {
                report.modules = Some(run_modules(cfg, opts, sleep, &store, today, &plan));
            }
            let m = report.modules.clone().unwrap_or_default();
            let attention =
                !plan.exclusions.is_empty() || !plan.disappeared.is_empty() || m.any_notes();
            let (code, text) = if m.any_error() {
                (
                    exit::MODULE_FAILED,
                    "provisioning ok, but a module failed (see modules)",
                )
            } else if m.any_violation() {
                (
                    exit::MODULE_GUARD,
                    "provisioning ok, but a module hit its safety threshold and changed nothing (see modules)",
                )
            } else if attention {
                (
                    exit::COMPLETED_WITH_EXCLUSIONS,
                    "ok, but records need attention: skipped records (exclusions), employees missing from AFAS while active (disappeared_while_active) or module notes (modules)",
                )
            } else {
                (exit::OK, "ok")
            };
            report.exit_code = code;
            report.result = text.into();
            (Ok(()), Some(plan))
        }
        Err(e) => {
            report.exit_code = e.exit_code();
            report.result = e.to_string();
            (Err(e), None)
        }
    };
    // Always write the report; an error doing so does not replace an earlier error.
    let write_res = serde_json::to_vec_pretty(&report)
        .map_err(|e| AppError::Internal(e.to_string()))
        .and_then(|j| store.write_report(&j));
    match (res, write_res) {
        (Err(e), _) | (Ok(()), Err(e)) => Err((e, Some(Box::new(report)))),
        (Ok(()), Ok(())) => Ok(RunResult { report, plan }),
    }
}

fn run_modules(
    cfg: &Config,
    opts: &RunOptions,
    sleep: &dyn Fn(Duration),
    store: &StateStore,
    today: NaiveDate,
    plan: &Plan,
) -> crate::modules::ModulesReport {
    use crate::modules::{Ctx, ModulesReport, load_state, people, run_all, save_state};
    let mut state = match load_state(store.dir()) {
        Ok(s) => s,
        Err(e) => {
            return ModulesReport {
                error: Some(e),
                ..Default::default()
            };
        }
    };
    let people = people(&plan.records, cfg.population.name.as_deref());
    let ctx = Ctx {
        cfg,
        people: &people,
        today,
        apply: opts.apply,
        use_system_proxy: opts.use_system_proxy,
        sleep,
        state_dir: store.dir(),
        actor: &opts.actor,
    };
    let mut rep = run_all(&ctx, &mut state);
    if opts.apply
        && let Err(e) = save_state(store.dir(), &state)
    {
        rep.error = Some(format!("module state not saved: {e}"));
    }
    rep
}

fn run_inner(
    cfg: &Config,
    opts: &RunOptions,
    sleep: &dyn Fn(Duration),
    store: &StateStore,
    today: NaiveDate,
    report: &mut Report,
) -> Result<Plan> {
    let previous = store.load()?;

    // Check secrets and certificate before fetching: better to fail right away.
    let afas_auth = afas::auth_header(&afas::read_token(&cfg.afas)?)?;
    let credential = if opts.apply {
        Some(Credential::from_config(&cfg.entra)?)
    } else {
        None
    };

    let afas_client = build_client(cfg.afas.timeout_secs, opts.use_system_proxy, &cfg.tls)
        .map_err(AppError::Config)?;
    let rows = afas::fetch_rows(&cfg.afas, &afas_auth, &afas_client, sleep)?;
    check_schema(&rows, &cfg.afas.fields).map_err(AppError::Source)?;

    let plan = build_plan(PlanInput {
        rows: &rows,
        fields: &cfg.afas.fields,
        policy: &cfg.policy,
        batch_size: cfg.upload.batch_size as usize,
        today,
        previous: previous.as_ref(),
        allow_mass_disable: opts.allow_mass_disable,
    });
    report.counts = plan.counts.clone();
    report.violations = plan.violations.clone();
    report.exclusions = plan.exclusions.clone();
    report.warnings = plan.warnings.clone();
    report.disappeared_while_active = plan.disappeared.clone();

    let requests = bulk_requests(&plan.records, cfg.upload.batch_size as usize);
    if let Some(path) = &opts.dump_payload {
        let j =
            serde_json::to_vec_pretty(&requests).map_err(|e| AppError::Internal(e.to_string()))?;
        write_atomic(path, &j)?;
    }

    if !plan.violations.is_empty() {
        let msg = plan
            .violations
            .iter()
            .map(|v| format!("[{}] {}", v.guard, v.message))
            .collect::<Vec<_>>()
            .join("; ");
        return Err(AppError::Guard(msg));
    }
    let Some(credential) = credential else {
        return Ok(plan); // dry-run: done
    };

    let entra_client = build_client(cfg.entra.timeout_secs, opts.use_system_proxy, &cfg.tls)
        .map_err(AppError::Config)?;
    let tokens = TokenProvider::new(&cfg.entra, &entra_client, credential, sleep);
    tokens.get(false)?; // test auth before the first upload
    let outcome = entra::upload_all(
        &requests,
        &cfg.entra,
        &cfg.upload,
        &entra_client,
        &tokens,
        sleep,
    )?;
    report.upload = Some(outcome);

    let state = State {
        version: STATE_VERSION,
        last_success_utc: chrono::Utc::now().to_rfc3339(),
        sent_total: plan.records.len(),
        records: plan
            .records
            .iter()
            .map(|r| {
                (
                    r.employee.employee_id.clone(),
                    RecordState { active: r.active },
                )
            })
            .collect(),
    };
    store.save(&state)?;
    Ok(plan)
}
