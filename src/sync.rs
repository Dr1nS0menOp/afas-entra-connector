// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The afas-entra-sync Authors
//! The full run: lock → AFAS → plan → checks → (upload) → state → preview → notifications.

use crate::afas;
use crate::config::Config;
use crate::entra::{self, Credential, TokenProvider, UploadOutcome};
use crate::error::{AppError, Result, exit};
use crate::http::build_client;
use crate::model::check_schema;
use crate::notify::{self, CheckLogsReport, Delivery, Outcome};
use crate::plan::{
    Counts, Exclusion, GuardViolation, ManagerGap, MissingRecord, Plan, PlanInput, UpnChange,
    Warning, build_plan,
};
use crate::preview::{self, Preview};
use crate::scim::{bulk_requests, sent_values};
use crate::state::{
    CHECK_LOGS_FILE, REPORT_FILE, RecordState, STATE_VERSION, State, StateStore, log_file,
    preview_file, write_atomic,
};
use chrono::NaiveDate;
use serde::Serialize;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone, Default)]
pub struct RunOptions {
    /// Without `apply` nothing is sent to Entra.
    pub apply: bool,
    /// Dry-run only: pretend it is this date.
    pub as_of: Option<NaiveDate>,
    pub allow_mass_disable: bool,
    /// Proceed when more records are new than `policy.max_new_per_run`.
    pub allow_mass_create: bool,
    /// Proceed when more sign-in names change than `policy.max_upn_changes_per_run`.
    pub allow_upn_changes: bool,
    /// Writes the SCIM payloads to this file (contains personal data).
    pub dump_payload: Option<PathBuf>,
    /// Writes the preview as a standalone HTML page to this file (contains personal data).
    pub preview_html: Option<PathBuf>,
    /// Test run: also send notifications (a sync always does, when configured).
    pub notify: bool,
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
    /// The same, with since when and why (kept until resolved).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing: Vec<MissingRecord>,
    /// Sign-in names that change in this run.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub upn_changes: Vec<UpnChange>,
    /// Managers who left (or cannot be linked) while employees still report to them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub manager_gaps: Vec<ManagerGap>,
    pub upload: Option<UploadOutcome>,
    /// Results of the optional modules (roles, joiner, leaver, webhook).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modules: Option<crate::modules::ModulesReport>,
    /// Things to act on that are not about records, e.g. a certificate about to expire.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notices: Vec<String>,
    /// What happens per account: totals, and where the full preview is.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preview: Option<preview::Summary>,
    /// Notifications sent after this run.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notifications: Vec<Delivery>,
    /// The log of this run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_file: Option<String>,
    pub result: String,
    pub exit_code: i32,
}

#[derive(Debug)]
pub struct RunResult {
    pub report: Report,
    pub plan: Option<Plan>,
    pub preview: Option<Preview>,
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
    let capture = crate::logcap::start();
    let started = chrono::Utc::now();
    let today = opts
        .as_of
        .unwrap_or_else(|| started.with_timezone(&cfg.tz()).date_naive());
    let mode = if opts.apply { "apply" } else { "dry-run" };
    tracing::info!(
        "{} started by {} (afas-entra-sync {}), reference date {today}{}",
        if opts.apply {
            "sync"
        } else {
            "test run (dry-run)"
        },
        opts.actor,
        env!("CARGO_PKG_VERSION"),
        cfg.population
            .name
            .as_deref()
            .map(|n| format!(", staff category {n}"))
            .unwrap_or_default()
    );

    let mut report = Report {
        mode,
        population: cfg.population.name.clone(),
        started_utc: started.to_rfc3339(),
        today: today.to_string(),
        counts: Counts::default(),
        violations: vec![],
        exclusions: vec![],
        warnings: vec![],
        disappeared_while_active: vec![],
        missing: vec![],
        upn_changes: vec![],
        manager_gaps: vec![],
        upload: None,
        modules: None,
        notices: Vec::new(),
        preview: None,
        notifications: Vec::new(),
        log_file: None,
        result: String::new(),
        exit_code: exit::OK,
    };

    let mut previous: Option<State> = None;
    let mut stopped_plan: Option<Plan> = None;
    let result = run_inner(
        cfg,
        opts,
        sleep,
        &store,
        today,
        &mut report,
        &mut previous,
        &mut stopped_plan,
    );
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
            // Certificates: a notice from 30 days before expiry; exit 3 from 7 days, so
            // monitoring raises it before sign-in starts failing.
            let (notices, urgent) =
                crate::ux::cert_notices(&crate::ux::certificates(cfg, chrono::Utc::now()));
            report.notices = notices;
            if urgent && report.exit_code == exit::OK {
                report.exit_code = exit::COMPLETED_WITH_EXCLUSIONS;
                report.result = "ok, but a certificate expires within 7 days (see notices)".into();
            }
            (Ok(()), Some(plan))
        }
        Err(e) => {
            report.exit_code = e.exit_code();
            report.result = e.to_string();
            if matches!(e, AppError::Guard(_)) {
                tracing::warn!("{e}");
            } else {
                tracing::error!("{e}");
            }
            (Err(e), None)
        }
    };

    // A safety stop still has a plan worth showing: that is when people need the preview most.
    let plan_for_view = plan.as_ref().or(stopped_plan.as_ref());
    let preview = plan_for_view.map(|p| build_preview(cfg, opts, sleep, p, previous.as_ref()));
    if let Some(pv) = &preview {
        let file = preview_file(opts.apply);
        match serde_json::to_vec_pretty(pv)
            .map_err(|e| AppError::Internal(e.to_string()))
            .and_then(|j| write_atomic(&store.dir().join(file), &j))
        {
            Ok(()) => report.preview = Some(pv.summary(file)),
            Err(e) => tracing::error!("preview not saved: {e}"),
        }
        if let Some(path) = &opts.preview_html {
            let html = preview::render_page(pv, Some(cfg.tz()));
            if let Err(e) = write_atomic(path, html.as_bytes()) {
                tracing::error!("preview page not written: {e}");
            }
        }
    }
    tracing::info!("finished: {} (exit {})", report.result, report.exit_code);

    // Notifications: after every sync (if configured), after a test run only on request.
    if (opts.apply || opts.notify) && report.exit_code != exit::LOCKED {
        report.notifications = notify_after_run(
            cfg,
            opts,
            sleep,
            &report,
            plan_for_view,
            previous.as_ref(),
            preview.as_ref(),
            capture.lines(),
            &store,
        );
    }

    // Always write the log and the report; an error doing so does not replace an earlier one.
    let log_path = store.dir().join(log_file(opts.apply));
    let mut log = capture.lines().join("\n");
    log.push('\n');
    if write_atomic(&log_path, log.as_bytes()).is_ok() {
        report.log_file = Some(log_path.display().to_string());
    }
    drop(capture);
    let write_res = serde_json::to_vec_pretty(&report)
        .map_err(|e| AppError::Internal(e.to_string()))
        .and_then(|j| store.write_report(opts.apply, &j));
    match (res, write_res) {
        (Err(e), _) | (Ok(()), Err(e)) => Err((e, Some(Box::new(report)))),
        (Ok(()), Ok(())) => Ok(RunResult {
            report,
            plan,
            preview,
        }),
    }
}

/// The preview of this run. A test run looks up Entra when an identity is available;
/// a sync compares with the previous state only (it must not depend on extra sign-ins).
fn build_preview(
    cfg: &Config,
    opts: &RunOptions,
    sleep: &dyn Fn(Duration),
    plan: &Plan,
    previous: Option<&State>,
) -> Preview {
    let (directory, directory_error) = if opts.apply {
        (None, None)
    } else {
        match preview::look_up(cfg, opts.use_system_proxy, sleep) {
            Ok(d) => {
                if let Some(d) = &d {
                    tracing::info!("preview: read {} accounts from Entra", d.users.len());
                }
                (d, None)
            }
            Err(e) => {
                tracing::warn!("preview: the look-up in Entra failed: {e}");
                (None, Some(e))
            }
        }
    };
    preview::build(preview::Input {
        cfg,
        plan,
        previous,
        directory: directory.as_ref(),
        directory_error,
        apply: opts.apply,
        created_utc: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    })
}

#[allow(clippy::too_many_arguments)]
fn notify_after_run(
    cfg: &Config,
    opts: &RunOptions,
    sleep: &dyn Fn(Duration),
    report: &Report,
    plan: Option<&Plan>,
    previous: Option<&State>,
    preview: Option<&Preview>,
    log: Vec<String>,
    store: &StateStore,
) -> Vec<Delivery> {
    if cfg.notify.as_ref().is_none_or(|n| !n.enabled) {
        return Vec::new();
    }
    let host = notify::host_name();
    let build = |names: bool| {
        notify::findings::from_sync(&notify::findings::SyncInput {
            cfg,
            report,
            plan,
            previous,
            preview: if opts.apply { None } else { preview },
            names,
            host: &host,
        })
    };
    let failed = !matches!(
        report.exit_code,
        exit::OK | exit::COMPLETED_WITH_EXCLUSIONS | exit::MODULE_GUARD | exit::MODULE_FAILED
    );
    let probe = build(false);
    let outcome = if failed {
        Outcome::Failure
    } else if probe.is_empty() {
        Outcome::Ok
    } else {
        Outcome::Attention
    };
    let source = if opts.apply { "Sync" } else { "Test run" };
    let facts = run_facts(cfg, opts, report, &host);
    let ctx = notify::Context {
        cfg,
        source: source.into(),
        host: host.clone(),
        log,
        log_path: Some(store.dir().join(log_file(opts.apply)).display().to_string()),
        report: serde_json::to_value(report).ok(),
        use_system_proxy: opts.use_system_proxy,
        sleep,
        now: chrono::Utc::now(),
    };
    let stateless = (!opts.apply).then_some(match outcome {
        Outcome::Failure => notify::render::Event::Failure,
        _ => notify::render::Event::Attention,
    });
    let sent = report.upload.as_ref().map(|_| report.counts.sent_total);
    notify::dispatch(&ctx, "sync", outcome, &build, &facts, sent, stateless)
}

fn run_facts(cfg: &Config, opts: &RunOptions, r: &Report, host: &str) -> Vec<(String, String)> {
    let started = chrono::DateTime::parse_from_rfc3339(&r.started_utc)
        .map(|t| {
            t.with_timezone(&cfg.tz())
                .format("%a %-d %b %Y, %H:%M")
                .to_string()
        })
        .unwrap_or_else(|_| r.started_utc.clone());
    let mut f = vec![(
        "Run".to_string(),
        format!(
            "{}, started by {}",
            if opts.apply {
                "Sync"
            } else {
                "Test run (dry-run)"
            },
            opts.actor
        ),
    )];
    if let Some(p) = &cfg.population.name {
        f.push(("Staff category".into(), p.clone()));
    }
    f.push(("Started".into(), started));
    f.push(("Reference date".into(), r.today.clone()));
    f.push((
        "Result".into(),
        format!("exit {}: {}", r.exit_code, r.result),
    ));
    if let Some(u) = &r.upload {
        f.push((
            "Sent".into(),
            format!(
                "{} employees in {} calls",
                r.counts.sent_total, u.calls_accepted
            ),
        ));
    } else if r.counts.rows_fetched > 0 {
        f.push((
            "AFAS".into(),
            format!(
                "{} rows, {} to send",
                r.counts.rows_fetched, r.counts.sent_total
            ),
        ));
    }
    f.push(("Server".into(), host.to_string()));
    f
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
        users: Default::default(),
    };
    let mut rep = run_all(&ctx, &mut state);
    if opts.apply
        && let Err(e) = save_state(store.dir(), &state)
    {
        rep.error = Some(format!("module state not saved: {e}"));
    }
    rep
}

#[allow(clippy::too_many_arguments)]
fn run_inner(
    cfg: &Config,
    opts: &RunOptions,
    sleep: &dyn Fn(Duration),
    store: &StateStore,
    today: NaiveDate,
    report: &mut Report,
    previous_out: &mut Option<State>,
    stopped_plan: &mut Option<Plan>,
) -> Result<Plan> {
    let previous = store.load()?;
    *previous_out = previous.clone();

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
    tracing::info!("AFAS: {} rows fetched", rows.len());
    check_schema(&rows, &cfg.afas.fields).map_err(AppError::Source)?;

    let plan = build_plan(PlanInput {
        rows: &rows,
        fields: &cfg.afas.fields,
        policy: &cfg.policy,
        batch_size: cfg.upload.batch_size as usize,
        today,
        previous: previous.as_ref(),
        allow_mass_disable: opts.allow_mass_disable,
        allow_mass_create: opts.allow_mass_create,
        allow_upn_changes: opts.allow_upn_changes,
    });
    let c = &plan.counts;
    tracing::info!(
        "plan: {} to send ({} active, {} new hires not started, {} departed, {} disabled once more outside the window), {} skipped (data errors), {} outside the date window, {} missing from AFAS while active, {} API calls",
        c.sent_total,
        c.sent_active,
        c.sent_inactive_prehire,
        c.sent_inactive_leaver,
        c.sent_inactive_outside_window,
        c.excluded_errors,
        c.skipped_future_start + c.skipped_old_leaver,
        c.disappeared_while_active,
        c.api_calls_needed
    );
    for x in &plan.exclusions {
        tracing::info!(
            "skipped {}: {}",
            x.employee_id.as_deref().unwrap_or("(no number)"),
            x.reason
        );
    }
    report.counts = plan.counts.clone();
    report.violations = plan.violations.clone();
    report.exclusions = plan.exclusions.clone();
    report.warnings = plan.warnings.clone();
    report.disappeared_while_active = plan.disappeared.clone();
    report.missing = plan.missing.clone();
    report.upn_changes = plan.upn_changes.clone();
    report.manager_gaps = plan.manager_gaps.clone();

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
        *stopped_plan = Some(plan);
        return Err(AppError::Guard(msg));
    }
    let Some(credential) = credential else {
        return Ok(plan); // dry-run: done
    };

    let entra_client = build_client(cfg.entra.timeout_secs, opts.use_system_proxy, &cfg.tls)
        .map_err(AppError::Config)?;
    let tokens = TokenProvider::new(&cfg.entra, &entra_client, credential, sleep);
    tokens.get(false)?; // test auth before the first upload
    tracing::info!("signed in to Entra ID; uploading {} calls", requests.len());
    let outcome = entra::upload_all(
        &requests,
        &cfg.entra,
        &cfg.upload,
        &entra_client,
        &tokens,
        sleep,
    )?;
    report.upload = Some(outcome);

    store.save(&next_state(&plan, previous.as_ref(), today))?;
    Ok(plan)
}

/// The state after a successful upload: what was sent (with its values), plus everyone
/// who was sent as active before and is missing now, so they keep being reported.
pub fn next_state(plan: &Plan, previous: Option<&State>, today: NaiveDate) -> State {
    let mut records: std::collections::BTreeMap<String, RecordState> = plan
        .records
        .iter()
        .map(|r| {
            (
                r.employee.employee_id.clone(),
                RecordState {
                    active: r.active,
                    sent: sent_values(r),
                    missing_since: None,
                },
            )
        })
        .collect();
    if let Some(prev) = previous {
        for m in &plan.missing {
            let before = prev
                .records
                .get(&m.employee_id)
                .cloned()
                .unwrap_or_default();
            records.insert(
                m.employee_id.clone(),
                RecordState {
                    active: true,
                    sent: before.sent,
                    missing_since: Some(before.missing_since.unwrap_or(today)),
                },
            );
        }
    }
    State {
        version: STATE_VERSION,
        last_success_utc: chrono::Utc::now().to_rfc3339(),
        sent_total: plan.records.len(),
        records,
    }
}

// ------------------------------------------------------------------ check-logs

/// Minutes after an upload before "nothing processed yet" is worth a warning.
pub const PROCESSING_GRACE_MINUTES: i64 = 10;

/// Reads the provisioning logs of the last `since_minutes`, writes `last-check-logs.json`
/// and notifies. Exit: 0 fine, 3 warnings (e.g. nothing processed), 50 failures, or the
/// error's own code.
pub fn check_logs(
    cfg: &Config,
    since_minutes: i64,
    use_system_proxy: bool,
    sleep: &dyn Fn(Duration),
) -> CheckLogsReport {
    let capture = crate::logcap::start();
    let now = chrono::Utc::now();
    let since = now - chrono::Duration::minutes(since_minutes);
    if let Err(e) = std::fs::create_dir_all(&cfg.state.dir) {
        tracing::error!(
            "cannot create state directory {}: {e}",
            cfg.state.dir.display()
        );
    }
    let res = (|| -> Result<entra::LogSummary> {
        let client = build_client(cfg.entra.timeout_secs, use_system_proxy, &cfg.tls)
            .map_err(AppError::Config)?;
        let cred = Credential::from_config(&cfg.entra)?;
        let tokens = TokenProvider::new(&cfg.entra, &client, cred, sleep);
        entra::read_logs(&cfg.entra, &client, &tokens, since)
    })();
    // The last sync that uploaded something.
    let last_upload = std::fs::read(cfg.state.dir.join(REPORT_FILE))
        .ok()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .filter(|r| r["mode"] == "apply" && r["upload"]["calls_accepted"].as_u64().unwrap_or(0) > 0)
        .and_then(|r| {
            Some((
                r["started_utc"].as_str()?.to_string(),
                r["upload"]["calls_accepted"].as_u64().unwrap_or(0),
            ))
        });
    let mut rep = CheckLogsReport {
        checked_utc: now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        since_utc: since.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        summary: None,
        warnings: Vec::new(),
        error: None,
        last_upload_utc: last_upload.as_ref().map(|(t, _)| t.clone()),
        exit_code: exit::OK,
    };
    match res {
        Ok(sum) => {
            tracing::info!(
                "provisioning logs since {}: {} entries, {} failed",
                rep.since_utc,
                sum.total,
                sum.failure
            );
            if let Some(w) = silence_warning(cfg, &sum, last_upload.as_ref(), since, now) {
                tracing::warn!("{w}");
                rep.warnings.push(w);
            }
            rep.exit_code = if sum.failure > 0 {
                exit::LOG_FAILURES
            } else if !rep.warnings.is_empty() {
                exit::COMPLETED_WITH_EXCLUSIONS
            } else {
                exit::OK
            };
            rep.summary = Some(sum);
        }
        Err(e) => {
            tracing::error!("{e}");
            rep.exit_code = e.exit_code();
            rep.error = Some(e.to_string());
        }
    }
    if let Ok(j) = serde_json::to_vec_pretty(&rep)
        && let Err(e) = write_atomic(&cfg.state.dir.join(CHECK_LOGS_FILE), &j)
    {
        tracing::error!("{CHECK_LOGS_FILE} not written: {e}");
    }
    if cfg.notify.as_ref().is_some_and(|n| n.enabled) {
        let host = notify::host_name();
        let build = |_names: bool| notify::findings::from_check_logs(&rep, cfg);
        let outcome = if build(false).is_empty() {
            Outcome::Ok
        } else {
            Outcome::Attention
        };
        let ctx = notify::Context {
            cfg,
            source: "Provisioning log check".into(),
            host: host.clone(),
            log: capture.lines(),
            log_path: None,
            report: serde_json::to_value(&rep).ok(),
            use_system_proxy,
            sleep,
            now,
        };
        let facts = vec![
            (
                "Run".to_string(),
                "Check of the provisioning logs".to_string(),
            ),
            (
                "Period".to_string(),
                format!("the last {since_minutes} minutes"),
            ),
            ("Result".to_string(), format!("exit {}", rep.exit_code)),
            ("Server".to_string(), host),
        ];
        notify::dispatch(&ctx, "logs", outcome, &build, &facts, None, None);
    }
    rep
}

/// "Nothing processed": the last upload is in the window, old enough to have been
/// processed, and no log entry is newer than it.
pub fn silence_warning(
    cfg: &Config,
    sum: &entra::LogSummary,
    last_upload: Option<&(String, u64)>,
    since: chrono::DateTime<chrono::Utc>,
    now: chrono::DateTime<chrono::Utc>,
) -> Option<String> {
    let (t, calls) = last_upload?;
    let up = chrono::DateTime::parse_from_rfc3339(t)
        .ok()?
        .with_timezone(&chrono::Utc);
    if up < since || now - up < chrono::Duration::minutes(PROCESSING_GRACE_MINUTES) {
        return None;
    }
    let processed = sum
        .latest_utc
        .as_deref()
        .and_then(|l| chrono::DateTime::parse_from_rfc3339(l).ok())
        .is_some_and(|l| l.with_timezone(&chrono::Utc) >= up);
    if processed {
        return None;
    }
    Some(format!(
        "The sync of {} uploaded {calls} calls, but the provisioning logs show nothing after it ({} minutes later). The provisioning job may be paused or in quarantine, or entra.job_id may point to another job.",
        up.with_timezone(&cfg.tz()).format("%Y-%m-%d %H:%M"),
        (now - up).num_minutes()
    ))
}
