//! Typed command-line contract applied after flags-2-env validation.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

/// Whole-company assessment CLI and webhook service.
#[derive(Clone, Debug, Parser)]
#[command(name = "canonical-auditor", version, about)]
pub struct Cli {
    /// Requested operation.
    #[command(subcommand)]
    pub command: Command,
}

/// Supported top-level operations.
#[derive(Clone, Debug, Subcommand)]
pub enum Command {
    /// Inspect reviewed framework metadata and deterministic rule coverage.
    Catalog(CatalogArgs),
    /// Validate manifest, evidence, and assessment program without writing a report.
    Validate(ValidateArgs),
    /// Run a deterministic whole-company assessment.
    Assess(AssessArgs),
    /// Run a dress-rehearsal or full-audit engagement.
    Audit(AuditArgs),
    /// Export a verified audit dossier as a complete report package.
    Package(PackageArgs),
    /// Render a constrained AI narrative prompt from an existing report.
    Prompt(PromptArgs),
    /// Run the signed inbound assessment/webhook HTTP service.
    Serve(ServeArgs),
}

/// Catalog output settings.
#[derive(Clone, Debug, Args)]
pub struct CatalogArgs {
    /// Human-readable table or complete JSON.
    #[arg(
        long,
        value_enum,
        default_value = "table",
        env = "CANONICAL_AUDITOR_CATALOG_FORMAT"
    )]
    pub format: CatalogFormat,
}

/// Validation input paths.
#[derive(Clone, Debug, Args)]
pub struct ValidateArgs {
    /// Company manifest JSON.
    #[arg(long, env = "CANONICAL_AUDITOR_VALIDATE_MANIFEST")]
    pub manifest: PathBuf,
    /// Evidence bundle JSON.
    #[arg(long, env = "CANONICAL_AUDITOR_VALIDATE_EVIDENCE")]
    pub evidence: PathBuf,
    /// Optional assessment program JSON; omission uses the reviewed built-in program.
    #[arg(long, env = "CANONICAL_AUDITOR_VALIDATE_PROGRAM")]
    pub program: Option<PathBuf>,
}

/// Deterministic assessment inputs and output policy.
#[derive(Clone, Debug, Args)]
pub struct AssessArgs {
    /// Company manifest JSON.
    #[arg(long, env = "CANONICAL_AUDITOR_ASSESS_MANIFEST")]
    pub manifest: PathBuf,
    /// Evidence bundle JSON.
    #[arg(long, env = "CANONICAL_AUDITOR_ASSESS_EVIDENCE")]
    pub evidence: PathBuf,
    /// Optional assessment program JSON; omission uses the reviewed built-in program.
    #[arg(long, env = "CANONICAL_AUDITOR_ASSESS_PROGRAM")]
    pub program: Option<PathBuf>,
    /// Report destination, or `-` for stdout.
    #[arg(
        long,
        short,
        default_value = "-",
        env = "CANONICAL_AUDITOR_ASSESS_OUTPUT"
    )]
    pub output: String,
    /// JSON or Markdown report.
    #[arg(
        long,
        value_enum,
        default_value = "markdown",
        env = "CANONICAL_AUDITOR_ASSESS_FORMAT"
    )]
    pub format: ReportFormat,
    /// Return exit code 2 for failed findings at or above this severity; `never` disables.
    #[arg(long, default_value = "high", env = "CANONICAL_AUDITOR_ASSESS_FAIL_ON")]
    pub fail_on: String,
}

/// Dress-rehearsal or full-audit inputs and output policy.
#[derive(Clone, Debug, Args)]
pub struct AuditArgs {
    /// Company manifest JSON.
    #[arg(long, env = "CANONICAL_AUDITOR_AUDIT_MANIFEST")]
    pub manifest: PathBuf,
    /// Evidence bundle JSON.
    #[arg(long, env = "CANONICAL_AUDITOR_AUDIT_EVIDENCE")]
    pub evidence: PathBuf,
    /// Audit engagement JSON.
    #[arg(long, env = "CANONICAL_AUDITOR_AUDIT_ENGAGEMENT")]
    pub engagement: PathBuf,
    /// Optional assessment program JSON; omission uses the reviewed built-in program.
    #[arg(long, env = "CANONICAL_AUDITOR_AUDIT_PROGRAM")]
    pub program: Option<PathBuf>,
    /// Dossier destination, or `-` for stdout.
    #[arg(
        long,
        short,
        default_value = "-",
        env = "CANONICAL_AUDITOR_AUDIT_OUTPUT"
    )]
    pub output: String,
    /// JSON or Markdown dossier output.
    #[arg(
        long,
        value_enum,
        default_value = "markdown",
        env = "CANONICAL_AUDITOR_AUDIT_FORMAT"
    )]
    pub format: ReportFormat,
    /// Return exit code 2 for exception controls at or above this severity; `never` disables.
    #[arg(long, default_value = "high", env = "CANONICAL_AUDITOR_AUDIT_FAIL_ON")]
    pub fail_on: String,
}

/// Complete report-package export settings.
#[derive(Clone, Debug, Args)]
pub struct PackageArgs {
    /// Existing audit dossier JSON.
    #[arg(long, env = "CANONICAL_AUDITOR_PACKAGE_DOSSIER")]
    pub dossier: PathBuf,
    /// New output directory; existing paths are refused.
    #[arg(long, env = "CANONICAL_AUDITOR_PACKAGE_OUTPUT_DIR")]
    pub output_dir: PathBuf,
}

/// AI prompt rendering inputs.
#[derive(Clone, Debug, Args)]
pub struct PromptArgs {
    /// Prompt name: evidence-review, executive-summary, gap-analysis, or remediation-plan.
    #[arg(long, env = "CANONICAL_AUDITOR_PROMPT_NAME")]
    pub name: String,
    /// Existing audit report JSON.
    #[arg(long, env = "CANONICAL_AUDITOR_PROMPT_REPORT")]
    pub report: PathBuf,
    /// Prompt destination, or `-` for stdout.
    #[arg(
        long,
        short,
        default_value = "-",
        env = "CANONICAL_AUDITOR_PROMPT_OUTPUT"
    )]
    pub output: String,
}

/// Signed HTTP service settings.
#[derive(Clone, Debug, Args)]
pub struct ServeArgs {
    /// Socket address. Non-loopback binding requires `CANONICAL_WEBHOOK_SECRET`.
    #[arg(
        long,
        default_value = "127.0.0.1:8080",
        env = "CANONICAL_AUDITOR_SERVE_BIND"
    )]
    pub bind: String,
    /// Maximum assessment request size in bytes.
    #[arg(
        long,
        default_value_t = 1_048_576,
        env = "CANONICAL_AUDITOR_SERVE_MAX_BODY_BYTES"
    )]
    pub max_body_bytes: usize,
}

/// Catalog serialization.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum CatalogFormat {
    /// Tab-separated summary.
    Table,
    /// Complete program JSON.
    Json,
}

/// Report serialization.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum ReportFormat {
    /// Machine-readable JSON.
    Json,
    /// Human-readable Markdown.
    Markdown,
}
