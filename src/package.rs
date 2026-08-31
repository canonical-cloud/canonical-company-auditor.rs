//! Complete, deterministic Markdown/JSON audit report packages.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use crate::AuditError;
use crate::audit::{AuditDossier, ExceptionRecord, verify_dossier};
use crate::engagement::ExceptionDisposition;
use crate::evidence::digest;

/// Audit package schema emitted by this release.
pub const PACKAGE_SCHEMA: &str = "canonical.audit-package/v1";

/// One generated report document and its integrity metadata.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PackageDocument {
    /// Stable safe file name.
    pub file_name: String,
    /// Document media type.
    pub media_type: String,
    /// SHA-256 of the exact UTF-8 content.
    pub sha256: String,
    /// Exact content length in bytes.
    pub bytes: usize,
    /// Generated content.
    pub content: String,
}

/// Value-free metadata written as `package-manifest.json` beside report documents.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditPackageManifest {
    /// Versioned package boundary.
    pub schema_version: String,
    /// Digest binding the dossier and every document.
    pub package_id: String,
    /// Source dossier identifier.
    pub dossier_id: String,
    /// Ordered document inventory.
    pub documents: Vec<PackageDocumentMetadata>,
}

/// Integrity metadata for one report document.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PackageDocumentMetadata {
    /// Stable safe file name.
    pub file_name: String,
    /// Document media type.
    pub media_type: String,
    /// SHA-256 of the exact UTF-8 content.
    pub sha256: String,
    /// Exact content length in bytes.
    pub bytes: usize,
}

/// In-memory package returned by the API and persisted by the CLI.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditPackage {
    /// Integrity manifest.
    pub manifest: AuditPackageManifest,
    /// Exact generated report documents.
    pub documents: Vec<PackageDocument>,
}

/// Builds a complete reviewer-ready report package from a verified dossier.
///
/// # Errors
///
/// Returns an [`AuditError`] if the dossier is invalid or report serialization fails.
pub fn build_audit_package(dossier: &AuditDossier) -> Result<AuditPackage, AuditError> {
    verify_dossier(dossier)?;
    let sources = [
        (
            "00-audit-report.md",
            "text/markdown",
            render_audit_report(dossier),
        ),
        (
            "01-control-testing.md",
            "text/markdown",
            render_controls(dossier),
        ),
        (
            "02-evidence-manifest.md",
            "text/markdown",
            render_evidence(dossier),
        ),
        (
            "03-evidence-requests.md",
            "text/markdown",
            render_requests(dossier),
        ),
        ("04-sampling.md", "text/markdown", render_sampling(dossier)),
        (
            "05-workpaper-index.md",
            "text/markdown",
            render_workpapers(dossier),
        ),
        (
            "06-findings-and-actions.md",
            "text/markdown",
            render_exceptions(dossier),
        ),
        ("07-audit-trail.md", "text/markdown", render_trail(dossier)),
        (
            "08-framework-crosswalk.md",
            "text/markdown",
            render_crosswalk(dossier),
        ),
        (
            "audit-dossier.json",
            "application/json",
            format!("{}\n", serde_json::to_string_pretty(dossier)?),
        ),
    ];
    let mut documents = Vec::with_capacity(sources.len());
    for (file_name, media_type, content) in sources {
        documents.push(PackageDocument {
            file_name: file_name.to_owned(),
            media_type: media_type.to_owned(),
            sha256: digest(&content.as_bytes())?,
            bytes: content.len(),
            content,
        });
    }
    let metadata = documents
        .iter()
        .map(PackageDocumentMetadata::from)
        .collect::<Vec<_>>();
    let package_id = digest(&(
        "canonical.audit-package-identity/v1",
        dossier.dossier_id.as_str(),
        &metadata,
    ))?;
    Ok(AuditPackage {
        manifest: AuditPackageManifest {
            schema_version: PACKAGE_SCHEMA.to_owned(),
            package_id,
            dossier_id: dossier.dossier_id.clone(),
            documents: metadata,
        },
        documents,
    })
}

/// Renders the primary human-readable audit engagement report.
///
/// # Errors
///
/// Returns an [`AuditError`] when the source dossier fails integrity verification.
pub fn render_dossier_markdown(dossier: &AuditDossier) -> Result<String, AuditError> {
    verify_dossier(dossier)?;
    Ok(render_audit_report(dossier))
}

/// Verifies all package document sizes, digests, metadata, and package identity.
///
/// # Errors
///
/// Returns an [`AuditError`] if package content or metadata was changed.
pub fn verify_audit_package(package: &AuditPackage) -> Result<(), AuditError> {
    if package.manifest.schema_version != PACKAGE_SCHEMA
        || package.manifest.documents.len() != package.documents.len()
    {
        return Err(AuditError::Integrity);
    }
    let mut names = BTreeSet::new();
    for (document, metadata) in package.documents.iter().zip(&package.manifest.documents) {
        if !names.insert(document.file_name.as_str())
            || metadata != &PackageDocumentMetadata::from(document)
            || document.bytes != document.content.len()
            || digest(&document.content.as_bytes())? != document.sha256
        {
            return Err(AuditError::Integrity);
        }
    }
    let expected = digest(&(
        "canonical.audit-package-identity/v1",
        package.manifest.dossier_id.as_str(),
        &package.manifest.documents,
    ))?;
    if expected != package.manifest.package_id {
        return Err(AuditError::Integrity);
    }
    Ok(())
}

impl From<&PackageDocument> for PackageDocumentMetadata {
    fn from(document: &PackageDocument) -> Self {
        Self {
            file_name: document.file_name.clone(),
            media_type: document.media_type.clone(),
            sha256: document.sha256.clone(),
            bytes: document.bytes,
        }
    }
}

fn render_audit_report(dossier: &AuditDossier) -> String {
    let mut output = String::from("# Whole-company audit engagement report\n\n");
    field(
        &mut output,
        "Company",
        &dossier.readiness_report.manifest.company_name,
    );
    field(&mut output, "Engagement", &dossier.engagement.engagement_id);
    field(&mut output, "Mode", &label(&dossier.engagement.mode));
    field(&mut output, "Phase", &label(&dossier.engagement.phase));
    field(&mut output, "Dossier", &dossier.dossier_id);
    field(&mut output, "Conclusion", &label(&dossier.conclusion));
    output.push_str("\n## Executive outcome\n\n");
    let summary = &dossier.summary;
    let _ = writeln!(
        output,
        "| Controls | Satisfactory | Exceptions | Evidence gaps | Not reviewed | Evidence coverage | Review coverage |\n| ---: | ---: | ---: | ---: | ---: | ---: | ---: |\n| {} | {} | {} | {} | {} | {} | {} |",
        summary.total_controls,
        summary.satisfactory_controls,
        summary.exception_controls,
        summary.evidence_gap_controls,
        summary.not_reviewed_controls,
        percent(summary.evidence_coverage_basis_points),
        percent(summary.review_coverage_basis_points),
    );
    output.push_str("\n## Objective and criteria\n\n");
    let _ = writeln!(
        output,
        "**Objective:** {}\n",
        escape(&dossier.engagement.objective)
    );
    let _ = writeln!(
        output,
        "**Criteria:** {}\n",
        escape(&dossier.engagement.criteria)
    );
    output.push_str("## Scope and period\n\n");
    field(&mut output, "Tenant", &dossier.engagement.tenant_id);
    field(&mut output, "Scope", &dossier.engagement.scope_id);
    field(
        &mut output,
        "Period",
        &format!(
            "{} through {} (inclusive Unix seconds)",
            dossier.engagement.period.starts_at, dossier.engagement.period.ends_at
        ),
    );
    output.push_str("\n## Framework profiles\n\n");
    for framework in &dossier.engagement.framework_ids {
        let _ = writeln!(output, "- `{}`", inline(framework));
    }
    output.push_str("\n## Open items\n\n");
    let _ = writeln!(
        output,
        "- Open evidence requests: {}\n- Open exceptions: {}\n- Management responses: {}",
        summary.open_evidence_requests, summary.open_exceptions, summary.management_responses
    );
    output.push_str("\n## Intended recipients\n\n");
    if dossier.engagement.report_recipients.is_empty() {
        output.push_str("No recipients recorded; this is a draft engagement package.\n");
    } else {
        for recipient in &dossier.engagement.report_recipients {
            let _ = writeln!(output, "- {}", escape(recipient));
        }
    }
    output.push_str("\n## Limitations\n\n");
    for limitation in &dossier.limitations {
        let _ = writeln!(output, "- {}", escape(limitation));
    }
    output
}

fn render_controls(dossier: &AuditDossier) -> String {
    let mut output = String::from("# Control testing matrix\n\n");
    output.push_str("| Rule | Category | Severity | Automated | Audit | Workpaper | Reviewer | Sample | Evidence | Exceptions |\n| --- | --- | --- | --- | --- | --- | --- | --- | ---: | ---: |\n");
    for control in &dossier.control_results {
        let _ = writeln!(
            output,
            "| `{}` | {} | {} | {} | {} | {} | {} | {} | {} | {} |",
            inline(&control.rule_id),
            escape(&control.category),
            control.severity,
            label(&control.automated_status),
            label(&control.audit_status),
            optional_code(control.workpaper_id.as_deref()),
            optional_code(control.reviewer_id.as_deref()),
            optional_code(control.sample_plan_id.as_deref()),
            control.evidence_ids.len(),
            control.exception_ids.len(),
        );
    }
    output
}

fn render_evidence(dossier: &AuditDossier) -> String {
    let mut output = String::from("# Evidence manifest and chain of custody\n\n");
    output.push_str("Normalized fact values and source artifacts are deliberately absent.\n\n");
    output.push_str("| Observation | External ID | Type | Subject | Source | Collected | Valid until | Facts digest | Attested | Rules |\n| --- | --- | --- | --- | --- | ---: | ---: | --- | --- | --- |\n");
    for evidence in &dossier.evidence_index {
        let rules = evidence
            .referenced_by_rule_ids
            .iter()
            .map(|value| format!("`{}`", inline(value)))
            .collect::<Vec<_>>()
            .join("<br>");
        let _ = writeln!(
            output,
            "| `{}` | `{}` | `{}` | `{}` | {} | {} | {} | `{}` | {} | {} |",
            inline(&evidence.observation_id),
            inline(&evidence.external_id),
            inline(&evidence.evidence_type),
            inline(&evidence.subject),
            escape(&evidence.source_kind),
            evidence.collected_at,
            evidence.valid_until,
            inline(&evidence.facts_sha256),
            evidence.attested,
            rules,
        );
    }
    output
}

fn render_requests(dossier: &AuditDossier) -> String {
    let mut output = String::from("# Evidence request register\n\n");
    output.push_str("| Request | Title | Owner | Due | Status | Rules | Evidence items |\n| --- | --- | --- | ---: | --- | --- | ---: |\n");
    for request in &dossier.engagement.evidence_requests {
        let _ = writeln!(
            output,
            "| `{}` | {} | `{}` | {} | {} | {} | {} |",
            inline(&request.request_id),
            escape(&request.title),
            inline(&request.owner_id),
            request.due_at,
            label(&request.status),
            request
                .rule_ids
                .iter()
                .map(|item| format!("`{}`", inline(item)))
                .collect::<Vec<_>>()
                .join("<br>"),
            request.evidence_external_ids.len(),
        );
    }
    output
}

fn render_sampling(dossier: &AuditDossier) -> String {
    let mut output = String::from("# Population and sample register\n\n");
    output.push_str("| Sample plan | Rule | Population | Population size | Method | Sample size | Selection digest count | Rationale |\n| --- | --- | --- | ---: | --- | ---: | ---: | --- |\n");
    for sample in &dossier.engagement.sample_plans {
        let _ = writeln!(
            output,
            "| `{}` | `{}` | `{}` | {} | {} | {} | {} | {} |",
            inline(&sample.sample_plan_id),
            inline(&sample.rule_id),
            inline(&sample.population_id),
            sample.population_size,
            label(&sample.method),
            sample.sample_size,
            sample.selected_item_fingerprints.len(),
            escape(&sample.rationale),
        );
    }
    output
}

fn render_workpapers(dossier: &AuditDossier) -> String {
    let mut output = String::from("# Workpaper index and review status\n\n");
    output.push_str("| Workpaper | Rule | Preparer | Prepared | Design | Operating | Evidence | Exceptions | Reviewer | Review |\n| --- | --- | --- | ---: | --- | --- | ---: | ---: | --- | --- |\n");
    for workpaper in &dossier.engagement.workpapers {
        let signoff = workpaper.reviewer_signoff.as_ref();
        let _ = writeln!(
            output,
            "| `{}` | `{}` | `{}` | {} | {} | {} | {} | {} | {} | {} |",
            inline(&workpaper.workpaper_id),
            inline(&workpaper.rule_id),
            inline(&workpaper.preparer_id),
            workpaper.prepared_at,
            label(&workpaper.design_conclusion),
            label(&workpaper.operating_conclusion),
            workpaper.evidence_external_ids.len(),
            workpaper.exceptions.len(),
            optional_code(signoff.map(|item| item.reviewer_id.as_str())),
            signoff.map_or_else(|| "pending".to_owned(), |item| label(&item.conclusion)),
        );
    }
    output
}

fn render_exceptions(dossier: &AuditDossier) -> String {
    let mut output = String::from("# Findings, exceptions, and management actions\n\n");
    if dossier.exceptions.is_empty() {
        output.push_str("No auditor-documented exceptions.\n");
        return output;
    }
    for record in &dossier.exceptions {
        render_exception(&mut output, record);
    }
    output
}

fn render_exception(output: &mut String, record: &ExceptionRecord) {
    let exception = &record.exception;
    let _ = writeln!(output, "## {}\n", escape(&exception.title));
    field(output, "Exception", &exception.exception_id);
    field(output, "Rule", &record.rule_id);
    field(output, "Workpaper", &record.workpaper_id);
    field(output, "Classification", &label(&exception.classification));
    field(output, "Disposition", &label(&exception.disposition));
    let _ = writeln!(output, "\n{}\n", escape(&exception.description));
    if let Some(response) = &record.management_response {
        output.push_str("### Management response\n\n");
        let _ = writeln!(output, "{}\n", escape(&response.response));
        let _ = writeln!(
            output,
            "**Action plan:** {}\n",
            escape(&response.action_plan)
        );
        field(output, "Owner", &response.owner_id);
        field(output, "Due", &response.due_at.to_string());
        field(output, "Status", &label(&response.status));
        output.push('\n');
    } else if !matches!(
        exception.disposition,
        ExceptionDisposition::Remediated | ExceptionDisposition::CompensatingControl
    ) {
        output.push_str("No management response is recorded.\n\n");
    }
}

fn render_trail(dossier: &AuditDossier) -> String {
    let mut output = String::from("# Content-addressed audit trail\n\n");
    output.push_str("| Sequence | Event | Actor | Occurred | Subject | Payload | Previous | Entry |\n| ---: | --- | --- | ---: | --- | --- | --- | --- |\n");
    for entry in &dossier.audit_trail {
        let _ = writeln!(
            output,
            "| {} | `{}` | `{}` | {} | `{}` | `{}` | {} | `{}` |",
            entry.event.sequence,
            inline(&entry.event.event_type),
            inline(&entry.event.actor_id),
            entry.event.occurred_at,
            inline(&entry.event.subject_id),
            inline(&entry.event.payload_sha256),
            optional_code(entry.previous_entry_sha256.as_deref()),
            inline(&entry.entry_sha256),
        );
    }
    output
}

fn render_crosswalk(dossier: &AuditDossier) -> String {
    let mut output = String::from("# Framework crosswalk\n\n");
    output.push_str("Mappings are directional references, not equivalence claims.\n\n");
    output.push_str("| Rule | Audit status | Framework | Reference |\n| --- | --- | --- | --- |\n");
    for control in &dossier.control_results {
        for mapping in &control.framework_mappings {
            let _ = writeln!(
                output,
                "| `{}` | {} | `{}` | {} |",
                inline(&control.rule_id),
                label(&control.audit_status),
                inline(&mapping.framework_id),
                escape(&mapping.reference),
            );
        }
    }
    output
}

fn field(output: &mut String, name: &str, value: &str) {
    let _ = writeln!(output, "**{}:** `{}`  ", escape(name), inline(value));
}

fn label<T: Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|item| item.as_str().map(ToOwned::to_owned))
        .unwrap_or_else(|| "unknown".to_owned())
}

fn percent(basis_points: u16) -> String {
    format!("{}.{:02}%", basis_points / 100, basis_points % 100)
}

fn optional_code(value: Option<&str>) -> String {
    value.map_or_else(|| "—".to_owned(), |item| format!("`{}`", inline(item)))
}

fn inline(value: &str) -> String {
    value.replace('`', "\\`").replace('|', "\\|")
}

fn escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace('*', "\\*")
        .replace('_', "\\_")
        .replace('[', "\\[")
        .replace(']', "\\]")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\n', " ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::ControlTestStatus;
    use crate::engagement::RequestStatus;

    #[test]
    fn percentages_are_exact_basis_points() {
        assert_eq!(percent(0), "0.00%");
        assert_eq!(percent(8_750), "87.50%");
        assert_eq!(percent(10_000), "100.00%");
    }

    #[test]
    fn request_status_serializes_as_public_label() {
        assert_eq!(label(&RequestStatus::Accepted), "accepted");
        assert_eq!(label(&ControlTestStatus::NotReviewed), "not_reviewed");
    }
}
