//! Whole-company assurance engine for deterministic, evidence-cited readiness reviews.
//!
//! The engine separates framework-neutral observations from framework overlays and keeps
//! AI-assisted narrative generation outside the evidence and decision boundary.

pub mod app;
pub mod audit;
// This is a handwritten consuming projection of the admitted external audit-config contract.
// Keep the wire-shaped bool fields and deterministic validation layout stable until generated
// adapters replace it; scope projection/test style exceptions here rather than weakening Clippy
// for the rest of the crate.
#[allow(
    clippy::bool_comparison,
    clippy::expect_used,
    clippy::must_use_candidate,
    clippy::ref_option,
    clippy::semicolon_if_nothing_returned,
    clippy::struct_excessive_bools,
    clippy::too_many_lines
)]
pub mod audit_config;
pub mod cli;
pub mod engagement;
pub mod engine;
pub mod evidence;
pub mod evidence_merge;
pub mod external_evidence;
pub mod flags;
pub mod model;
pub mod native_readiness_evidence;
pub mod operational_evidence;
pub mod package;
pub mod program;
pub mod report;
pub mod scanner_signals;
pub mod server;

use thiserror::Error;

/// Errors safe to surface at the CLI or JSON API boundary.
#[derive(Debug, Error)]
pub enum AuditError {
    /// Input failed a domain invariant.
    #[error("invalid {field}: {reason}")]
    Invalid {
        /// Stable field name.
        field: &'static str,
        /// Safe explanation that does not reflect input secrets.
        reason: String,
    },
    /// Input used an unsupported schema or program version.
    #[error("unsupported version: {0}")]
    UnsupportedVersion(String),
    /// An evidence digest or deterministic identifier did not verify.
    #[error("evidence integrity verification failed")]
    Integrity,
    /// The requested tenant or scope did not match the evidence boundary.
    #[error("evidence is outside the requested tenant or scope")]
    ScopeDenied,
    /// A named catalog item does not exist.
    #[error("unknown catalog item: {0}")]
    UnknownCatalogItem(String),
    /// JSON serialization or parsing failed.
    #[error("JSON boundary error: {0}")]
    Json(#[from] serde_json::Error),
    /// TOML parsing failed at the audit-config boundary.
    #[error("TOML boundary error: {0}")]
    Toml(#[from] toml::de::Error),
    /// Filesystem or socket I/O failed.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// A server bind address or request violated server policy.
    #[error("server policy error: {0}")]
    ServerPolicy(String),
}
