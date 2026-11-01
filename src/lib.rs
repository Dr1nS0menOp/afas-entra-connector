// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The afas-entra-sync Authors
//! afas-entra-sync — delivers AFAS employees to Microsoft Entra
//! API-driven inbound provisioning. See README.md.

#![forbid(unsafe_code)]
// No panics in production code: errors are values. (Tests may use unwrap.)
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

pub mod afas;
pub mod config;
pub mod doctor;
pub mod entra;
pub mod error;
pub mod graph;
pub mod http;
pub mod install;
pub mod model;
pub mod modules;
pub mod plan;
pub mod scim;
pub mod state;
pub mod sync;
pub mod tls;
pub mod ux;
pub mod web;
