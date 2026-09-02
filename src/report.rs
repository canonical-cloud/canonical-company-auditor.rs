//! Safe Markdown reports and constrained AI narrative prompt rendering.

use std::fmt::Write as _;
use std::str::FromStr;

use crate::AuditError;
use crate::model::{AuditReport, Finding, FindingStatus};

/// Supported narrative assistance tasks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PromptKind {
    /// Board- and executive-readable summary.
    ExecutiveSummary,
    /// Evidence quality and gap review.
    EvidenceReview,
    /// Cross-framework gap analysis.
    GapAnalysis,
    /// Prioritized remediation plan.
    RemediationPlan,
}

impl PromptKind {
    /// Public names accepted by CLI and API routes.
    pub const NAMES: [&'static str; 4] = [
        "evidence-review",
        "executive-summary",
        "gap-analysis",
        "remediation-plan",
    ];

    /// Returns the reviewed prompt instructions.
    #[must_use]
    pub fn template(self) -> &'static str {
        match self {
            Self::ExecutiveSummary => include_str!("../prompts/executive-summary.md"),
            Self::EvidenceReview => include_str!("../prompts/evidence-review.md"),
            Self::GapAnalysis => include_str!("../prompts/gap-analysis.md"),
            Self::RemediationPlan => include_str!("../prompts/remediation-plan.md"),
        }
    }

    /// Returns the stable public name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExecutiveSummary => "executive-summary",
            Self::EvidenceReview => "evidence-review",
            Self::GapAnalysis => "gap-analysis",
            Self::RemediationPlan => "remediation-plan",
        }
    }
}

impl FromStr for PromptKind {
    type Err = AuditError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "executive-summary" => Ok(Self::ExecutiveSummary),
            "evidence-review" => Ok(Self::EvidenceReview),
            "gap-analysis" => Ok(Self::GapAnalysis),
            "remediation-plan" => Ok(Self::RemediationPlan),
            _ => Err(AuditError::UnknownCatalogItem(value.to_owned())),
        }
    }
}

/// Renders a deterministic report without including raw normalized evidence values.
#[must_use]
pub fn render_markdown(report: &AuditReport) -> String {
    let mut output = String::new();
    output.push_str("# Whole-company readiness assessment\n\n");
    push_field(&mut output, "Company", &report.manifest.company_name);
    push_field(&mut output, "Tenant", &report.manifest.tenant_id);
    push_field(&mut output, "Scope", &report.manifest.scope_id);
    push_field(&mut output, "Report", &report.report_id);
    push_field(&mut output, "Manifest", &report.manifest_sha256);
    push_field(&mut output, "Evidence", &report.evidence_sha256);
    push_field(&mut output, "Program", &report.program_sha256);
    output.push_str("\n## Outcome\n\n");
    let _ = writeln!(
        output,
        "| Passed | Failed | Unknown | High/critical failures |\n| ---: | ---: | ---: | ---: |\n| {} | {} | {} | {} |\n",
        report.summary.passed,
        report.summary.failed,
        report.summary.unknown,
        report.summary.high_or_critical
    );

    output.push_str("\n## Framework profiles\n\n");
    for framework in &report.manifest.frameworks {
        let _ = writeln!(output, "- `{}`", escape_inline(framework));
    }

    for (heading, status) in [
        ("Findings", FindingStatus::Fail),
        ("Evidence gaps", FindingStatus::Unknown),
        ("Satisfied tests", FindingStatus::Pass),
    ] {
        let _ = write!(output, "\n## {heading}\n\n");
        let selected = report
            .findings
            .iter()
            .filter(|finding| finding.status == status)
            .collect::<Vec<_>>();
        if selected.is_empty() {
            output.push_str("None.\n");
        } else {
            for finding in selected {
                render_finding(&mut output, finding);
            }
        }
    }

    output.push_str("\n## Limitations\n\n");
    for limitation in &report.limitations {
        let _ = writeln!(output, "- {}", escape_text(limitation));
    }
    output
}

/// Builds an AI-ready prompt where assessment JSON is visibly untrusted data.
///
/// # Errors
///
/// Returns an [`AuditError`] when the report cannot be serialized.
pub fn render_prompt(kind: PromptKind, report: &AuditReport) -> Result<String, AuditError> {
    let serialized = serde_json::to_string_pretty(report)?;
    let mut output = String::new();
    output.push_str(kind.template().trim());
    output.push_str("\n\nBEGIN UNTRUSTED ASSESSMENT DATA\n");
    for line in serialized.lines() {
        output.push_str("DATA ");
        output.push_str(line);
        output.push('\n');
    }
    output.push_str("END UNTRUSTED ASSESSMENT DATA\n");
    Ok(output)
}

fn render_finding(output: &mut String, finding: &Finding) {
    let _ = writeln!(
        output,
        "### {} — {}\n",
        escape_text(&finding.title),
        finding.severity
    );
    push_field(output, "Finding ID", &finding.finding_id);
    push_field(output, "Rule", &finding.rule_id);
    push_field(output, "Category", &finding.category);
    push_field(output, "Subject", &finding.subject);
    let _ = write!(output, "\n{}\n\n", escape_text(&finding.summary));
    let _ = writeln!(
        output,
        "**Remediation:** {}\n",
        escape_text(&finding.remediation)
    );
    if !finding.evidence_ids.is_empty() {
        output.push_str("**Evidence IDs:**\n\n");
        for evidence_id in &finding.evidence_ids {
            let _ = writeln!(output, "- `{}`", escape_inline(evidence_id));
        }
        output.push('\n');
    }
    if !finding.framework_mappings.is_empty() {
        output.push_str("**Framework references:**\n\n");
        for mapping in &finding.framework_mappings {
            let _ = writeln!(
                output,
                "- `{}` — {}\n",
                escape_inline(&mapping.framework_id),
                escape_text(&mapping.reference)
            );
        }
        output.push('\n');
    }
}

fn push_field(output: &mut String, label: &str, value: &str) {
    let _ = writeln!(
        output,
        "**{}:** `{}`  ",
        escape_text(label),
        escape_inline(value)
    );
}

fn escape_inline(value: &str) -> String {
    value.replace('`', "\\`")
}

fn escape_text(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('*', "\\*")
        .replace('_', "\\_")
        .replace('[', "\\[")
        .replace(']', "\\]")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prompt_names_round_trip() -> Result<(), AuditError> {
        for name in PromptKind::NAMES {
            let kind = PromptKind::from_str(name)?;
            assert_eq!(kind.as_str(), name);
        }
        Ok(())
    }
}
