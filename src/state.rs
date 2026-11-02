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

pub const STATE_VERSION: u32 = 1;
const STATE_FILE: &str = "state.json";
const LOCK_FILE: &str = "afas-entra-sync.lock";
pub const REPORT_FILE: &str = "last-report.json";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub version: u32,
    pub last_success_utc: String,
    pub sent_total: usize,
    pub records: BTreeMap<String, RecordState>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RecordState {
    pub active: bool,
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
        let mut opts = OpenOptions::new();
        opts.create(true).truncate(false).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let file = opts
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
        let state: State = serde_json::from_str(&text).map_err(|e| {
            AppError::Config(format!(
                "state file {} is corrupt ({e}); repair it or delete it deliberately",
                path.display()
            ))
        })?;
        if state.version != STATE_VERSION {
            return Err(AppError::Config(format!(
                "unknown state version {}",
                state.version
            )));
        }
        if state.sent_total != state.records.len() {
            return Err(AppError::Config(
                "state file is inconsistent (sent_total does not match)".into(),
            ));
        }
        Ok(Some(state))
    }

    pub fn save(&self, state: &State) -> Result<()> {
        let json =
            serde_json::to_vec_pretty(state).map_err(|e| AppError::Internal(e.to_string()))?;
        write_atomic(&self.dir.join(STATE_FILE), &json)
    }

    pub fn write_report(&self, json: &[u8]) -> Result<()> {
        write_atomic(&self.dir.join(REPORT_FILE), json)
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
