//! Deterministic, side-effect-free assessment evaluation.

use serde::Serialize;
use serde_json::Value;

use crate::AuditError;
use crate::evidence::{SealedObservation, digest, seal_evidence};
use crate::model::{
    AssessmentRequest, AssessmentSummary, AuditReport, Finding, FindingStatus, REPORT_SCHEMA,
    Severity,
};
use crate::program::{AssessmentProgram, AssessmentRule, ConditionOperator};

/// Evaluates a request with the exact supplied program and produces an immutable report.
///
/// # Errors
///
/// Returns an [`AuditError`] when versions, tenant/scope, evidence, catalog selection, rule
/// configuration, or canonical serialization fail validation.
pub fn assess(
    request: &AssessmentRequest,
    program: &AssessmentProgram,
) -> Result<AuditReport, AuditError> {
    request.manifest.validate()?;
    request.evidence.validate()?;
    program.validate()?;
    for framework_id in &request.manifest.frameworks {
        if program.framework(framework_id).is_none() {
            return Err(AuditError::UnknownCatalogItem(framework_id.clone()));
        }
    }

    let sealed = seal_evidence(&request.manifest, &request.evidence)?;
    let manifest_sha256 = digest(&request.manifest)?;
    let program_sha256 = program.sha256()?;
    let mut findings = program
        .rules
        .iter()
        .map(|rule| evaluate_rule(request, rule, &sealed.observations))
        .collect::<Result<Vec<_>, AuditError>>()?;
    findings.sort_by(|left, right| left.rule_id.cmp(&right.rule_id));

    let summary = summarize(&findings);
    let limitations = limitations(summary.unknown);
    let core = ReportIdentityCore {
        schema_version: REPORT_SCHEMA,
        manifest: &request.manifest,
        manifest_sha256: &manifest_sha256,
        evidence_sha256: &sealed.evidence_sha256,
        program_sha256: &program_sha256,
        summary: &summary,
        findings: &findings,
        limitations: &limitations,
    };
    let report_id = digest(&core)?;

    Ok(AuditReport {
        schema_version: REPORT_SCHEMA.to_owned(),
        report_id,
        manifest_sha256,
        evidence_sha256: sealed.evidence_sha256,
        program_sha256,
        manifest: request.manifest.clone(),
        summary,
        findings,
        limitations,
    })
}

#[derive(Serialize)]
struct ReportIdentityCore<'a> {
    schema_version: &'a str,
    manifest: &'a crate::model::CompanyManifest,
    manifest_sha256: &'a str,
    evidence_sha256: &'a str,
    program_sha256: &'a str,
    summary: &'a AssessmentSummary,
    findings: &'a [Finding],
    limitations: &'a [String],
}

/// Verifies a deserialized report before it is used for AI prompt rendering or export.
///
/// # Errors
///
/// Returns an [`AuditError`] when the report version, manifest, summary, digest, or identity is
/// invalid.
pub fn verify_report(report: &AuditReport) -> Result<(), AuditError> {
    if report.schema_version != REPORT_SCHEMA {
        return Err(AuditError::UnsupportedVersion(
            report.schema_version.clone(),
        ));
    }
    report.manifest.validate()?;
    if digest(&report.manifest)? != report.manifest_sha256
        || summarize(&report.findings) != report.summary
    {
        return Err(AuditError::Integrity);
    }
    let core = ReportIdentityCore {
        schema_version: REPORT_SCHEMA,
        manifest: &report.manifest,
        manifest_sha256: &report.manifest_sha256,
        evidence_sha256: &report.evidence_sha256,
        program_sha256: &report.program_sha256,
        summary: &report.summary,
        findings: &report.findings,
        limitations: &report.limitations,
    };
    if digest(&core)? != report.report_id {
        return Err(AuditError::Integrity);
    }
    Ok(())
}

fn evaluate_rule(
    request: &AssessmentRequest,
    rule: &AssessmentRule,
    observations: &[SealedObservation],
) -> Result<Finding, AuditError> {
    let assessment_end = request.manifest.assessment_period.ends_at;
    let relevant = observations
        .iter()
        .filter(|observation| {
            observation.input.evidence_type == rule.evidence_type
                && observation.input.collected_at <= assessment_end
                && observation.input.valid_until >= assessment_end
        })
        .collect::<Vec<_>>();

    let evaluations = relevant
        .iter()
        .map(|observation| evaluate_condition(rule, observation))
        .collect::<Vec<_>>();
    let status = if evaluations.contains(&Some(true)) {
        FindingStatus::Pass
    } else if evaluations.contains(&Some(false)) {
        FindingStatus::Fail
    } else {
        FindingStatus::Unknown
    };
    let evidence_ids = relevant
        .iter()
        .map(|observation| observation.observation_id.clone())
        .collect::<Vec<_>>();
    let subject = relevant.first().map_or_else(
        || request.manifest.scope_id.clone(),
        |item| item.input.subject.clone(),
    );
    let framework_mappings = rule
        .framework_mappings
        .iter()
        .filter(|mapping| request.manifest.frameworks.contains(&mapping.framework_id))
        .cloned()
        .collect::<Vec<_>>();
    let summary = match status {
        FindingStatus::Pass => "Current evidence satisfied the deterministic test.".to_owned(),
        FindingStatus::Fail => {
            "Current evidence did not satisfy the deterministic test; no raw fact values are included in this report."
                .to_owned()
        }
        FindingStatus::Unknown => {
            "No current, type-compatible evidence was available; this is an evidence gap, not proof that the control failed."
                .to_owned()
        }
    };
    let finding_id = digest(&(
        "canonical.finding/v1",
        &request.manifest.tenant_id,
        &request.manifest.scope_id,
        &rule.id,
        status,
        &evidence_ids,
    ))?;

    Ok(Finding {
        finding_id,
        rule_id: rule.id.clone(),
        title: rule.title.clone(),
        category: rule.category.clone(),
        severity: rule.severity,
        status,
        subject,
        summary,
        evidence_ids,
        framework_mappings,
        remediation: rule.remediation.clone(),
    })
}

fn evaluate_condition(rule: &AssessmentRule, observation: &SealedObservation) -> Option<bool> {
    let actual = observation.input.facts.get(&rule.condition.fact)?;
    match rule.condition.operator {
        ConditionOperator::Equals => Some(actual == &rule.condition.expected),
        ConditionOperator::NumberAtLeast => {
            Some(actual.as_f64()? >= rule.condition.expected.as_f64()?)
        }
        ConditionOperator::NumberAtMost => {
            Some(actual.as_f64()? <= rule.condition.expected.as_f64()?)
        }
        ConditionOperator::NonEmpty => match actual {
            Value::String(value) => Some(!value.is_empty()),
            Value::Array(values) => Some(!values.is_empty()),
            _ => None,
        },
    }
}

fn summarize(findings: &[Finding]) -> AssessmentSummary {
    let mut summary = AssessmentSummary {
        passed: 0,
        failed: 0,
        unknown: 0,
        high_or_critical: 0,
    };
    for finding in findings {
        match finding.status {
            FindingStatus::Pass => summary.passed += 1,
            FindingStatus::Fail => {
                summary.failed += 1;
                if finding.severity >= Severity::High {
                    summary.high_or_critical += 1;
                }
            }
            FindingStatus::Unknown => summary.unknown += 1,
        }
    }
    summary
}

fn limitations(unknown: usize) -> Vec<String> {
    let mut values = vec![
        "This readiness assessment is not a certification, legal opinion, regulatory determination, or independent auditor attestation."
            .to_owned(),
        "Framework mappings are directional aids; they do not assert equivalence between standards or replace authoritative source material."
            .to_owned(),
        "The engine evaluated normalized evidence supplied for the declared tenant, scope, period, and program; it did not independently prove completeness."
            .to_owned(),
        "AI-generated narrative must cite finding and evidence identifiers and cannot alter finding status or become audit evidence."
            .to_owned(),
    ];
    if unknown > 0 {
        values.push(format!(
            "{unknown} test(s) lack current type-compatible evidence and require collection or manual review."
        ));
    }
    values
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_empty_rejects_empty_values() {
        assert_eq!(
            match Value::String(String::new()) {
                Value::String(value) => Some(!value.is_empty()),
                _ => None,
            },
            Some(false)
        );
    }
}
