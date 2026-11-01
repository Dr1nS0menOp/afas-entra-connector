// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The afas-entra-sync Authors
//! Error types and exit codes.
//!
//! Every error has a fixed exit code so Semaphore or another scheduler can
//! tell configuration errors, safety stops and network problems apart.

use thiserror::Error;

/// Program exit codes. Anything other than `OK` means: take a look.
pub mod exit {
    /// Everything processed, nothing excluded.
    pub const OK: i32 = 0;
    /// Run completed, but records need attention: excluded because of data errors,
    /// or sent as active last run and now missing from the upload.
    pub const COMPLETED_WITH_EXCLUSIONS: i32 = 3;
    /// Configuration invalid or unreadable.
    pub const CONFIG: i32 = 10;
    /// Another run is already in progress (lock file held).
    pub const LOCKED: i32 = 11;
    /// A safety threshold was hit; NOTHING was uploaded.
    pub const GUARD: i32 = 20;
    /// AFAS unreachable, or the response does not match the configuration.
    pub const SOURCE: i32 = 30;
    /// Getting a token from Entra ID failed.
    pub const AUTH: i32 = 40;
    /// Upload to the provisioning API failed (possibly partially uploaded).
    pub const UPLOAD: i32 = 41;
    /// Provisioning logs contain failed records.
    pub const LOG_FAILURES: i32 = 50;
    /// Provisioning done, but a module hit its safety threshold and changed nothing.
    pub const MODULE_GUARD: i32 = 21;
    /// Provisioning done, but a module failed (sign-in, Graph or webhook error).
    pub const MODULE_FAILED: i32 = 42;
    /// `check-tls`: an endpoint does not meet the `[tls]` policy.
    pub const TLS: i32 = 60;
    /// Unexpected internal error.
    pub const INTERNAL: i32 = 70;
}

#[derive(Debug, Error)]
pub enum AppError {
    #[error("configuration error: {0}")]
    Config(String),
    #[error("another run is already active (lock: {0})")]
    Locked(String),
    #[error("safety stop, nothing was uploaded: {0}")]
    Guard(String),
    #[error("AFAS error: {0}")]
    Source(String),
    #[error("Entra ID authentication error: {0}")]
    Auth(String),
    #[error("upload error: {0}")]
    Upload(String),
    #[error("internal error: {0}")]
    Internal(String),
}

impl AppError {
    pub fn exit_code(&self) -> i32 {
        match self {
            AppError::Config(_) => exit::CONFIG,
            AppError::Locked(_) => exit::LOCKED,
            AppError::Guard(_) => exit::GUARD,
            AppError::Source(_) => exit::SOURCE,
            AppError::Auth(_) => exit::AUTH,
            AppError::Upload(_) => exit::UPLOAD,
            AppError::Internal(_) => exit::INTERNAL,
        }
    }
}

pub type Result<T> = std::result::Result<T, AppError>;
