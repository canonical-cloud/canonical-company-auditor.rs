//! Command orchestration and bounded file/stdout boundaries.

use std::fmt::Write as _;
use std::fs::{File, OpenOptions, create_dir};
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::de::DeserializeOwned;
use serde_json::json;

use crate::AuditError;
use crate::audit::{AuditDossier, ControlTestStatus, run_audit};
use crate::cli::{
    AssessArgs, AuditArgs, CatalogArgs, CatalogFormat, Cli, Command, PackageArgs, PromptArgs,
    ReportFormat, ServeArgs, ValidateArgs,
};
use crate::engagement::AuditEngagement;
use crate::engine::{assess, verify_report};
use crate::model::{
    AssessmentRequest, AuditReport, CompanyManifest, EvidenceBundle, FindingStatus, Severity,
};
use crate::package::{build_audit_package, render_dossier_markdown};
use crate::program::{AssessmentProgram, built_in_program};
use crate::report::{PromptKind, render_markdown, render_prompt};
use crate::server::{ServeConfig, run};

const MAX_INPUT_BYTES: u64 = 10 * 1024 * 1024;

/// Process-level success or deterministic finding-threshold failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Exit {
    /// Command completed and no configured threshold was crossed.
    Success,
    /// Report was written, but one or more failed findings crossed the threshold.
    FindingThreshold,
}

/// Executes one parsed command.
///
/// # Errors
///
/// Returns an [`AuditError`] when validation, assessment, I/O, prompting, or service startup
/// fails.
pub async fn execute(cli: Cli) -> Result<Exit, AuditError> {
    match cli.command {
        Command::Catalog(arguments) => catalog(&arguments),
        Command::Validate(arguments) => validate(&arguments),
        Command::Assess(arguments) => assess_command(&arguments),
        Command::Audit(arguments) => audit_command(&arguments),
        Command::Package(arguments) => package(&arguments),
        Command::Prompt(arguments) => prompt(&arguments),
        Command::Serve(arguments) => serve(arguments).await,
    }
}

fn catalog(arguments: &CatalogArgs) -> Result<Exit, AuditError> {
    let program = built_in_program()?;
    let output = match arguments.format {
        CatalogFormat::Json => format!("{}\n", serde_json::to_string_pretty(&program)?),
        CatalogFormat::Table => {
            let mut text = String::from("id\tversion\tauthority\tredistribution\n");
            for framework in &program.frameworks {
                let _ = writeln!(
                    text,
                    "{}\t{}\t{}\t{}",
                    framework.id, framework.version, framework.authority, framework.redistribution
                );
            }
            let _ = writeln!(text, "\nrules\t{}", program.rules.len());
            text
        }
    };
    write_output("-", &output)?;
    Ok(Exit::Success)
}

fn validate(arguments: &ValidateArgs) -> Result<Exit, AuditError> {
    let request = read_request(&arguments.manifest, &arguments.evidence)?;
    let program = read_program(arguments.program.as_ref())?;
    let report = assess(&request, &program)?;
    let output = serde_json::to_string_pretty(&json!({
        "valid": true,
        "reportId": report.report_id,
        "manifestSha256": report.manifest_sha256,
        "evidenceSha256": report.evidence_sha256,
        "programSha256": report.program_sha256,
        "summary": report.summary
    }))?;
    write_output("-", &format!("{output}\n"))?;
    Ok(Exit::Success)
}

fn assess_command(arguments: &AssessArgs) -> Result<Exit, AuditError> {
    let request = read_request(&arguments.manifest, &arguments.evidence)?;
    let program = read_program(arguments.program.as_ref())?;
    let report = assess(&request, &program)?;
    let output = match arguments.format {
        ReportFormat::Json => format!("{}\n", serde_json::to_string_pretty(&report)?),
        ReportFormat::Markdown => render_markdown(&report),
    };
    write_output(&arguments.output, &output)?;

    let threshold = parse_threshold(&arguments.fail_on)?;
    let crossed = threshold.is_some_and(|minimum| {
        report
            .findings
            .iter()
            .any(|finding| finding.status == FindingStatus::Fail && finding.severity >= minimum)
    });
    Ok(if crossed {
        Exit::FindingThreshold
    } else {
        Exit::Success
    })
}

fn audit_command(arguments: &AuditArgs) -> Result<Exit, AuditError> {
    let request = read_request(&arguments.manifest, &arguments.evidence)?;
    let engagement = read_json::<AuditEngagement>(&arguments.engagement)?;
    let program = read_program(arguments.program.as_ref())?;
    let dossier = run_audit(&request, &engagement, &program)?;
    let output = match arguments.format {
        ReportFormat::Json => format!("{}\n", serde_json::to_string_pretty(&dossier)?),
        ReportFormat::Markdown => render_dossier_markdown(&dossier)?,
    };
    write_output(&arguments.output, &output)?;

    let threshold = parse_threshold(&arguments.fail_on)?;
    let crossed = threshold.is_some_and(|minimum| {
        dossier.control_results.iter().any(|control| {
            control.audit_status == ControlTestStatus::Exception && control.severity >= minimum
        })
    });
    Ok(if crossed {
        Exit::FindingThreshold
    } else {
        Exit::Success
    })
}

fn package(arguments: &PackageArgs) -> Result<Exit, AuditError> {
    let dossier = read_json::<AuditDossier>(&arguments.dossier)?;
    let package = build_audit_package(&dossier)?;
    let manifest = format!("{}\n", serde_json::to_string_pretty(&package.manifest)?);
    create_dir(&arguments.output_dir)?;
    for document in &package.documents {
        write_new_file(
            &arguments.output_dir.join(&document.file_name),
            document.content.as_bytes(),
        )?;
    }
    write_new_file(
        &arguments.output_dir.join("package-manifest.json"),
        manifest.as_bytes(),
    )?;
    Ok(Exit::Success)
}

fn prompt(arguments: &PromptArgs) -> Result<Exit, AuditError> {
    let report: AuditReport = read_json(&arguments.report)?;
    verify_report(&report)?;
    let kind = PromptKind::from_str(&arguments.name)?;
    let output = render_prompt(kind, &report)?;
    write_output(&arguments.output, &output)?;
    Ok(Exit::Success)
}

async fn serve(arguments: ServeArgs) -> Result<Exit, AuditError> {
    run(ServeConfig {
        bind: arguments.bind,
        max_body_bytes: arguments.max_body_bytes,
    })
    .await?;
    Ok(Exit::Success)
}

fn read_request(manifest: &Path, evidence: &Path) -> Result<AssessmentRequest, AuditError> {
    Ok(AssessmentRequest {
        manifest: read_json::<CompanyManifest>(manifest)?,
        evidence: read_json::<EvidenceBundle>(evidence)?,
    })
}

fn read_program(path: Option<&PathBuf>) -> Result<AssessmentProgram, AuditError> {
    match path {
        Some(path) => {
            let bytes = read_bounded(path)?;
            AssessmentProgram::from_json(&bytes)
        }
        None => built_in_program(),
    }
}

fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T, AuditError> {
    let bytes = read_bounded(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, AuditError> {
    let file = File::open(path)?;
    let mut bytes = Vec::new();
    file.take(MAX_INPUT_BYTES + 1).read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_INPUT_BYTES {
        return Err(AuditError::Invalid {
            field: "input",
            reason: format!("file exceeds {MAX_INPUT_BYTES} bytes"),
        });
    }
    Ok(bytes)
}

fn write_output(path: &str, contents: &str) -> Result<(), AuditError> {
    if path == "-" {
        let stdout = std::io::stdout();
        let mut writer = BufWriter::new(stdout.lock());
        writer.write_all(contents.as_bytes())?;
        writer.flush()?;
        return Ok(());
    }
    let file = OpenOptions::new().create_new(true).write(true).open(path)?;
    let mut writer = BufWriter::new(file);
    writer.write_all(contents.as_bytes())?;
    writer.flush()?;
    writer.get_ref().sync_all()?;
    Ok(())
}

fn write_new_file(path: &Path, contents: &[u8]) -> Result<(), AuditError> {
    let file = OpenOptions::new().create_new(true).write(true).open(path)?;
    let mut writer = BufWriter::new(file);
    writer.write_all(contents)?;
    writer.flush()?;
    writer.get_ref().sync_all()?;
    Ok(())
}

fn parse_threshold(value: &str) -> Result<Option<Severity>, AuditError> {
    if value == "never" {
        Ok(None)
    } else {
        Severity::parse(value).map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threshold_parsing_is_fail_closed() {
        assert_eq!(parse_threshold("never").ok(), Some(None));
        assert_eq!(parse_threshold("high").ok(), Some(Some(Severity::High)));
        assert!(parse_threshold("urgent").is_err());
    }
}
