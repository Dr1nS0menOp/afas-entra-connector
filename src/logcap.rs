// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The afas-entra-sync Authors
//! Keeps the log lines of one run, so the full log can be written next to the report and
//! sent along with a notification.
//!
//! `main` installs [`Layer`] next to the normal log output. A run calls [`start`]; every
//! log event on that thread is then kept until the returned [`Capture`] is dropped. Per
//! thread, so runs started from the admin GUI (each on its own thread) and parallel tests
//! never mix their lines.

use std::cell::RefCell;
use std::fmt::Write as _;
use tracing::field::{Field, Visit};

/// More lines than this are not kept (a run with endless retries must not eat memory).
pub const MAX_LINES: usize = 20_000;

thread_local! {
    static BUF: RefCell<Option<Vec<String>>> = const { RefCell::new(None) };
}

/// Active capture on this thread; stops when dropped.
pub struct Capture {
    _private: (),
}

/// Starts keeping log lines on this thread (an earlier capture is replaced).
pub fn start() -> Capture {
    BUF.with(|b| *b.borrow_mut() = Some(Vec::new()));
    Capture { _private: () }
}

impl Capture {
    /// The lines so far.
    pub fn lines(&self) -> Vec<String> {
        BUF.with(|b| b.borrow().clone().unwrap_or_default())
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        BUF.with(|b| *b.borrow_mut() = None);
    }
}

/// Adds a line to the capture of this thread, if there is one.
pub fn push(line: String) {
    BUF.with(|b| {
        if let Some(v) = b.borrow_mut().as_mut() {
            if v.len() < MAX_LINES {
                v.push(line);
            } else if v.len() == MAX_LINES {
                v.push(format!(
                    "… more than {MAX_LINES} lines; the rest is only in the system log"
                ));
            }
        }
    });
}

/// Turns an event into `message key=value …`.
#[derive(Default)]
struct Line {
    message: String,
    fields: String,
}

impl Visit for Line {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message.push_str(value);
        } else {
            let _ = write!(self.fields, " {}={value}", field.name());
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            let _ = write!(self.message, "{value:?}");
        } else {
            let _ = write!(self.fields, " {}={value:?}", field.name());
        }
    }
}

/// Formats one log line the way it appears in the run log.
pub fn format_line(level: &tracing::Level, message: &str, fields: &str) -> String {
    format!(
        "{} {:<5} {message}{fields}",
        chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ"),
        level.as_str()
    )
}

/// The `tracing` layer that feeds the capture.
pub struct Layer;

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Layer {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let active = BUF.with(|b| b.borrow().is_some());
        if !active {
            return;
        }
        let mut l = Line::default();
        event.record(&mut l);
        push(format_line(event.metadata().level(), &l.message, &l.fields));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_subscriber::prelude::*;

    #[test]
    fn lines_are_kept_per_thread_while_capturing() {
        let sub = tracing_subscriber::registry().with(Layer);
        tracing::subscriber::with_default(sub, || {
            tracing::info!("before");
            let c = start();
            tracing::info!(call = 3, "uploaded");
            tracing::warn!("retrying");
            std::thread::spawn(|| tracing::info!("other thread"))
                .join()
                .unwrap();
            let lines = c.lines();
            assert_eq!(lines.len(), 2, "{lines:?}");
            assert!(lines[0].ends_with("INFO  uploaded call=3"), "{}", lines[0]);
            assert!(lines[1].contains("WARN  retrying"));
            drop(c);
            tracing::info!("after");
            assert!(start().lines().is_empty());
        });
    }
}
