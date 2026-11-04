// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The afas-entra-sync Authors
//! State of the last successful run, the lock file and the report.
//! Writes are atomic: temporary file first, fsync, then rename.

use crate::error::{AppError, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

/// 2 (0.11): the values sent last time and employees missing from AFAS are kept.
/// Version 1 files are read and upgraded on the next successful run.
pub const STATE_VERSION: u32 = 2;
const STATE_FILE: &str = "state.json";
const LOCK_FILE: &str = "afas-entra-sync.lock";
/// Report of the last real sync (`--apply`). Monitoring reads this one.
pub const REPORT_FILE: &str = "last-report.json";
/// Report of the last test run (dry-run). Kept apart so a manual test run never hides
/// the result of a scheduled sync from monitoring.
pub const DRY_RUN_REPORT_FILE: &str = "last-dry-run-report.json";
/// What the last sync did, record by record (contains personal data).
pub const PREVIEW_FILE: &str = "last-preview.json";
/// What the last test run would do, record by record (contains personal data).
pub const DRY_RUN_PREVIEW_FILE: &str = "last-dry-run-preview.json";
/// Log of the last sync and of the last test run.
pub const RUN_LOG_FILE: &str = "last-run.log";
pub const DRY_RUN_LOG_FILE: &str = "last-dry-run.log";
/// Result of the last `check-logs`.
pub const CHECK_LOGS_FILE: &str = "last-check-logs.json";

/// The report file for a run mode ("apply" or "dry-run").
pub fn report_file(apply: bool) -> &'static str {
    if apply {
        REPORT_FILE
    } else {
        DRY_RUN_REPORT_FILE
    }
}

pub fn preview_file(apply: bool) -> &'static str {
    if apply {
        PREVIEW_FILE
    } else {
        DRY_RUN_PREVIEW_FILE
    }
}

pub fn log_file(apply: bool) -> &'static str {
    if apply {
        RUN_LOG_FILE
    } else {
        DRY_RUN_LOG_FILE
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub version: u32,
    pub last_success_utc: String,
    /// Records sent in the last successful run (the missing ones are not counted).
    pub sent_total: usize,
    pub records: BTreeMap<String, RecordState>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RecordState {
    pub active: bool,
    /// The values sent last time (attribute → value, see `scim::sent_values`): what the
    /// test run compares with, and how a changed sign-in name (UPN) is noticed. Empty in
    /// state files written before 0.11.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub sent: BTreeMap<String, String>,
    /// Sent as active before, missing from the upload since this date. Such a record is
    /// kept and reported on every run until the employee is back in AFAS or someone marks
    /// it as handled (`missing ack`); it is never disabled automatically.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub missing_since: Option<chrono::NaiveDate>,
}

impl RecordState {
    pub fn new(active: bool) -> Self {
        RecordState {
            active,
            ..Default::default()
        }
    }

    /// The sign-in name sent last time, if known.
    pub fn upn(&self) -> Option<&str> {
        self.sent.get("userName").map(String::as_str)
    }

    pub fn is_missing(&self) -> bool {
        self.missing_since.is_some()
    }
}

pub struct StateStore {
    dir: PathBuf,
}

/// Holds the exclusive lock until this object is dropped.
pub struct RunLock {
    _file: File,
}

impl StateStore {
    pub fn new(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir).map_err(|e| {
            AppError::Config(format!(
                "cannot create state directory {}: {e}",
                dir.display()
            ))
        })?;
        Ok(Self {
            dir: dir.to_path_buf(),
        })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn lock(&self) -> Result<RunLock> {
        let path = self.dir.join(LOCK_FILE);
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .map_err(|e| AppError::Config(format!("cannot open lock file: {e}")))?;
        match file.try_lock() {
            Ok(()) => Ok(RunLock { _file: file }),
            Err(std::fs::TryLockError::WouldBlock) => {
                Err(AppError::Locked(path.display().to_string()))
            }
            Err(std::fs::TryLockError::Error(e)) => {
                Err(AppError::Config(format!("lock failed: {e}")))
            }
        }
    }

    /// `Ok(None)` if there is no state yet (first run). A corrupt or
    /// unknown state is an error: then we do not know what the last run did.
    pub fn load(&self) -> Result<Option<State>> {
        let path = self.dir.join(STATE_FILE);
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(AppError::Config(format!(
                    "cannot read {}: {e}",
                    path.display()
                )));
            }
        };
        let mut state: State = serde_json::from_str(&text).map_err(|e| {
            AppError::Config(format!(
                "state file {} is corrupt ({e}); repair it or delete it deliberately",
                path.display()
            ))
        })?;
        // Version 1 has the same shape without the new optional fields: upgrade in memory.
        if state.version != STATE_VERSION && state.version != 1 {
            return Err(AppError::Config(format!(
                "unknown state version {} (this program writes version {STATE_VERSION}; a newer program wrote it?)",
                state.version
            )));
        }
        state.version = STATE_VERSION;
        let sent = state.records.values().filter(|r| !r.is_missing()).count();
        if state.sent_total != sent {
            return Err(AppError::Config(
                "state file is inconsistent (sent_total does not match)".into(),
            ));
        }
        Ok(Some(state))
    }

    /// Marks employees that are missing from AFAS as handled: they are forgotten and no
    /// longer reported. `ids` empty = all of them. Returns the ids removed.
    pub fn acknowledge_missing(&self, ids: &[String]) -> Result<Vec<String>> {
        let _lock = self.lock()?;
        let Some(mut state) = self.load()? else {
            return Ok(Vec::new());
        };
        let wanted: Vec<String> = state
            .records
            .iter()
            .filter(|(id, r)| r.is_missing() && (ids.is_empty() || ids.contains(id)))
            .map(|(id, _)| id.clone())
            .collect();
        if let Some(bad) = ids.iter().find(|i| !wanted.contains(i)) {
            return Err(AppError::Config(format!(
                "employee number {bad} is not on the list of employees missing from AFAS (see: missing list)"
            )));
        }
        for id in &wanted {
            state.records.remove(id);
        }
        self.save(&state)?;
        Ok(wanted)
    }

    pub fn save(&self, state: &State) -> Result<()> {
        let json =
            serde_json::to_vec_pretty(state).map_err(|e| AppError::Internal(e.to_string()))?;
        write_atomic(&self.dir.join(STATE_FILE), &json)
    }

    /// Writes the report of a sync (`apply`) or of a test run.
    pub fn write_report(&self, apply: bool, json: &[u8]) -> Result<()> {
        write_atomic(&self.dir.join(report_file(apply)), json)
    }
}

/// Refuses a secret file (AFAS token, private key) that group or others can read or
/// write, like ssh does for private keys. Linux/Unix only; on Windows use NTFS ACLs.
pub fn check_private_file(path: &Path, what: &str) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let md = std::fs::metadata(path)
            .map_err(|e| AppError::Config(format!("cannot read {what} {}: {e}", path.display())))?;
        if !md.is_file() {
            return Err(AppError::Config(format!(
                "{what} {} is not a regular file",
                path.display()
            )));
        }
        let mode = md.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(AppError::Config(format!(
                "{what} {} is accessible by group or others (mode {mode:o}); run: chmod 600 {}",
                path.display(),
                path.display()
            )));
        }
        // A file owned by another (non-root) user could be replaced by that user,
        // so the owner must be this user or root.
        let me = std::fs::metadata("/proc/self").map(|m| m.uid()).ok();
        if let Some(me) = me
            && md.uid() != me
            && md.uid() != 0
        {
            return Err(AppError::Config(format!(
                "{what} {} is owned by uid {}, not by this user or root",
                path.display(),
                md.uid()
            )));
        }
    }
    #[cfg(not(unix))]
    let _ = (path, what);
    Ok(())
}

/// Atomic write with restricted permissions (contains employee numbers).
pub fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    let io = |e: std::io::Error| {
        AppError::Internal(format!("writing to {} failed: {e}", path.display()))
    };
    {
        let mut opts = OpenOptions::new();
        opts.create(true).write(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp).map_err(io)?;
        f.write_all(data).map_err(io)?;
        f.sync_all().map_err(io)?;
    }
    std::fs::rename(&tmp, path).map_err(io)?;
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        // Make sure the rename itself is on disk too.
        if let Ok(d) = File::open(parent) {
            let _ = d.sync_all();
        }
    }
    Ok(())
}
