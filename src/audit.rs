//! Auditor-grade engagement evaluation layered over the deterministic readiness engine.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::AuditError;
use crate::engagement::{
    AuditEngagement, AuditException, EngagementEvent, EngagementPhase, ExceptionClassification,
    ExceptionDisposition, ManagementResponse, RequestStatus, ReviewConclusion, Workpaper,
    WorkpaperConclusion,
};
use crate::engine::{assess, verify_report};
use crate::evidence::{digest, seal_evidence};
use crate::model::{
    AssessmentRequest, AuditReport, EvidenceSource, Finding, FindingStatus, FrameworkMapping,
    Severity,
};
use crate::program::AssessmentProgram;

/// Audit dossier schema emitted by this release.
pub const DOSSIER_SCHEMA: &str = "canonical.audit-dossier/v1";

/// Wire request for a dress rehearsal or full audit.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditRequest {
    /// Deterministic readiness inputs.
    #[serde(flatten)]
    pub assessment: AssessmentRequest,
    /// Engagement plan, fieldwork, review, and response record.
    pub engagement: AuditEngagement,
}

/// Tool-generated conclusion for the engagement record.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditConclusion {
    /// Every control is reviewed without a failed test or exception.
    Satisfactory,
    /// Review is complete, with documented exceptions that do not make the record incomplete.
    SatisfactoryWithExceptions,
    /// Material failed tests or exceptions undermine the evaluated objectives.
    Unsatisfactory,
    /// Evidence, workpaper, request, or review activity is incomplete.
    Incomplete,
}

/// Combined automated and auditor status for one control test.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlTestStatus {
    /// Automated evidence and reviewed auditor work both support the objective.
    Satisfactory,
    /// A failed test, workpaper conclusion, contradiction, or exception requires attention.
    Exception,
    /// Current evidence or completed testing is insufficient.
    EvidenceGap,
    /// No workpaper exists for the test.
    NotReviewed,
}

/// Counts used by dashboards and complete report packages.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DossierSummary {
    /// Total control tests in the selected program.
    pub total_controls: usize,
    /// Tests with satisfactory automated and auditor results.
    pub satisfactory_controls: usize,
    /// Tests with one or more exceptions.
    pub exception_controls: usize,
    /// Tests lacking sufficient evidence or completed procedures.
    pub evidence_gap_controls: usize,
    /// Tests not yet documented in a workpaper.
    pub not_reviewed_controls: usize,
    /// Controls with at least one current normalized evidence observation, in basis points.
    pub evidence_coverage_basis_points: u16,
    /// Controls with an approved reviewed workpaper, in basis points.
    pub review_coverage_basis_points: u16,
    /// Evidence requests that remain open, submitted, or rejected.
    pub open_evidence_requests: usize,
    /// Total documented exceptions.
    pub total_exceptions: usize,
    /// Exceptions not remediated or covered by an accepted compensating control.
    pub open_exceptions: usize,
    /// Management responses attached to exceptions.
    pub management_responses: usize,
}

/// Auditor-grade result for one program rule.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ControlTestResult {
    /// Canonical-authored rule identifier.
    pub rule_id: String,
    /// Test title.
    pub title: String,
    /// Whole-company workstream.
    pub category: String,
    /// Failure materiality.
    pub severity: Severity,
    /// Deterministic readiness status.
    pub automated_status: FindingStatus,
    /// Combined status used by the audit dossier.
    pub audit_status: ControlTestStatus,
    /// Workpaper identifier when the procedure was documented.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workpaper_id: Option<String>,
    /// Design conclusion from the workpaper.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub design_conclusion: Option<WorkpaperConclusion>,
    /// Operating conclusion from the workpaper.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operating_conclusion: Option<WorkpaperConclusion>,
    /// Approved reviewer identifier when review is complete.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewer_id: Option<String>,
    /// Sample plan used for population testing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sample_plan_id: Option<String>,
    /// Content-addressed evidence observations supporting the automated test.
    pub evidence_ids: Vec<String>,
    /// Documented exception identifiers.
    pub exception_ids: Vec<String>,
    /// Selected framework references.
    pub framework_mappings: Vec<FrameworkMapping>,
}

/// Safe evidence index entry; normalized fact values are intentionally absent.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceIndexEntry {
    /// Content-addressed observation identifier.
    pub observation_id: String,
    /// Stable source-system identifier.
    pub external_id: String,
    /// Framework-neutral evidence capability.
    pub evidence_type: String,
    /// Evaluated subject.
    pub subject: String,
    /// Manual, connector, or runtime-probe source family.
    pub source_kind: String,
    /// Collection time.
    pub collected_at: i64,
    /// Evidence expiration time.
    pub valid_until: i64,
    /// Digest of normalized facts, not their values.
    pub facts_sha256: String,
    /// Whether the source supplied an attestation reference.
    pub attested: bool,
    /// Rules that cited this observation.
    pub referenced_by_rule_ids: Vec<String>,
}

/// Exception enriched with its rule, workpaper, and management response.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExceptionRecord {
    /// Rule associated with the exception.
    pub rule_id: String,
    /// Workpaper that documented the exception.
    pub workpaper_id: String,
    /// Auditor-documented exception.
    pub exception: AuditException,
    /// Management response when supplied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub management_response: Option<ManagementResponse>,
}

/// One hash-chained audit-trail event.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditTrailEntry {
    /// Original ordered event.
    #[serde(flatten)]
    pub event: EngagementEvent,
    /// Previous entry digest; absent on the first event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_entry_sha256: Option<String>,
    /// Digest binding this event to the preceding entry.
    pub entry_sha256: String,
}

/// Immutable, evidence-indexed audit engagement output.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditDossier {
    /// Versioned dossier boundary.
    pub schema_version: String,
    /// Deterministic identifier for the complete dossier.
    pub dossier_id: String,
    /// Digest of the exact engagement record.
    pub engagement_sha256: String,
    /// Tool-generated conclusion, never an independent attestation.
    pub conclusion: AuditConclusion,
    /// Complete engagement plan and fieldwork record.
    pub engagement: AuditEngagement,
    /// Deterministic readiness result used as the automated-testing layer.
    pub readiness_report: AuditReport,
    /// Aggregate engagement counts and coverage.
    pub summary: DossierSummary,
    /// Combined control-test results.
    pub control_results: Vec<ControlTestResult>,
    /// Value-free evidence chain-of-custody index.
    pub evidence_index: Vec<EvidenceIndexEntry>,
    /// Exceptions with associated management responses.
    pub exceptions: Vec<ExceptionRecord>,
    /// Content-addressed engagement history.
    pub audit_trail: Vec<AuditTrailEntry>,
    /// Limitations that must survive every report rendering.
    pub limitations: Vec<String>,
}

/// Runs a dress rehearsal or full-audit engagement against exact assessment inputs.
///
/// # Errors
///
/// Returns an [`AuditError`] when inputs, engagement references, evidence, workpapers, or
/// canonical identity fail validation.
pub fn run_audit(
    request: &AssessmentRequest,
    engagement: &AuditEngagement,
    program: &AssessmentProgram,
) -> Result<AuditDossier, AuditError> {
    engagement.validate_against(&request.manifest, &request.evidence, program)?;
    let readiness_report = assess(request, program)?;
    let sealed = seal_evidence(&request.manifest, &request.evidence)?;
    let workpapers = engagement
        .workpapers
        .iter()
        .map(|item| (item.rule_id.as_str(), item))
        .collect::<BTreeMap<_, _>>();
    let findings = readiness_report
        .findings
        .iter()
        .map(|item| (item.rule_id.as_str(), item))
        .collect::<BTreeMap<_, _>>();

    let mut control_results = Vec::with_capacity(program.rules.len());
    for rule in &program.rules {
        let finding = findings
            .get(rule.id.as_str())
            .ok_or(AuditError::Integrity)?;
        control_results.push(control_result(
            finding,
            workpapers.get(rule.id.as_str()).copied(),
        ));
    }
    control_results.sort_by(|left, right| left.rule_id.cmp(&right.rule_id));

    let responses = engagement
        .management_responses
        .iter()
        .map(|item| (item.exception_id.as_str(), item))
        .collect::<BTreeMap<_, _>>();
    let mut exceptions = engagement
        .workpapers
        .iter()
        .flat_map(|workpaper| {
            workpaper
                .exceptions
                .iter()
                .map(|exception| ExceptionRecord {
                    rule_id: workpaper.rule_id.clone(),
                    workpaper_id: workpaper.workpaper_id.clone(),
                    exception: exception.clone(),
                    management_response: responses
                        .get(exception.exception_id.as_str())
                        .map(|item| (*item).clone()),
                })
        })
        .collect::<Vec<_>>();
    exceptions.sort_by(|left, right| {
        left.exception
            .exception_id
            .cmp(&right.exception.exception_id)
    });

    let evidence_index = evidence_index(&sealed.observations, &readiness_report.findings);
    let audit_trail = build_audit_trail(&engagement.events)?;
    let summary = summarize(engagement, &control_results, &exceptions);
    let conclusion = conclude(engagement, &control_results, &exceptions);
    let limitations = limitations(engagement);
    let engagement_sha256 = digest(engagement)?;
    let core = DossierIdentityCore {
        schema_version: DOSSIER_SCHEMA,
        engagement_sha256: &engagement_sha256,
        conclusion,
        engagement,
        readiness_report: &readiness_report,
        summary: &summary,
        control_results: &control_results,
        evidence_index: &evidence_index,
        exceptions: &exceptions,
        audit_trail: &audit_trail,
        limitations: &limitations,
    };
    let dossier_id = digest(&core)?;

    Ok(AuditDossier {
        schema_version: DOSSIER_SCHEMA.to_owned(),
        dossier_id,
        engagement_sha256,
        conclusion,
        engagement: engagement.clone(),
        readiness_report,
        summary,
        control_results,
        evidence_index,
        exceptions,
        audit_trail,
        limitations,
    })
}

/// Verifies a deserialized dossier before rendering or packaging.
///
/// # Errors
///
/// Returns an [`AuditError`] if the report, engagement, summaries, trail, or identity changed.
pub fn verify_dossier(dossier: &AuditDossier) -> Result<(), AuditError> {
    if dossier.schema_version != DOSSIER_SCHEMA {
        return Err(AuditError::UnsupportedVersion(
            dossier.schema_version.clone(),
        ));
    }
    dossier.engagement.validate()?;
    verify_report(&dossier.readiness_report)?;
    if digest(&dossier.engagement)? != dossier.engagement_sha256
        || build_audit_trail(&dossier.engagement.events)? != dossier.audit_trail
        || summarize(
            &dossier.engagement,
            &dossier.control_results,
            &dossier.exceptions,
        ) != dossier.summary
        || conclude(
            &dossier.engagement,
            &dossier.control_results,
            &dossier.exceptions,
        ) != dossier.conclusion
    {
        return Err(AuditError::Integrity);
    }
    let core = DossierIdentityCore {
        schema_version: DOSSIER_SCHEMA,
        engagement_sha256: &dossier.engagement_sha256,
        conclusion: dossier.conclusion,
        engagement: &dossier.engagement,
        readiness_report: &dossier.readiness_report,
        summary: &dossier.summary,
        control_results: &dossier.control_results,
        evidence_index: &dossier.evidence_index,
        exceptions: &dossier.exceptions,
        audit_trail: &dossier.audit_trail,
        limitations: &dossier.limitations,
    };
    if digest(&core)? != dossier.dossier_id {
        return Err(AuditError::Integrity);
    }
    Ok(())
}

#[derive(Serialize)]
struct DossierIdentityCore<'a> {
    schema_version: &'a str,
    engagement_sha256: &'a str,
    conclusion: AuditConclusion,
    engagement: &'a AuditEngagement,
    readiness_report: &'a AuditReport,
    summary: &'a DossierSummary,
    control_results: &'a [ControlTestResult],
    evidence_index: &'a [EvidenceIndexEntry],
    exceptions: &'a [ExceptionRecord],
    audit_trail: &'a [AuditTrailEntry],
    limitations: &'a [String],
}

fn control_result(finding: &Finding, workpaper: Option<&Workpaper>) -> ControlTestResult {
    let audit_status = match workpaper {
        None => ControlTestStatus::NotReviewed,
        Some(item)
            if finding.status == FindingStatus::Unknown
                || matches!(item.design_conclusion, WorkpaperConclusion::NotTested)
                || matches!(item.operating_conclusion, WorkpaperConclusion::NotTested) =>
        {
            ControlTestStatus::EvidenceGap
        }
        Some(item)
            if finding.status == FindingStatus::Fail
                || matches!(item.design_conclusion, WorkpaperConclusion::Ineffective)
                || matches!(item.operating_conclusion, WorkpaperConclusion::Ineffective)
                || !item.exceptions.is_empty() =>
        {
            ControlTestStatus::Exception
        }
        Some(_) => ControlTestStatus::Satisfactory,
    };
    ControlTestResult {
        rule_id: finding.rule_id.clone(),
        title: finding.title.clone(),
        category: finding.category.clone(),
        severity: finding.severity,
        automated_status: finding.status,
        audit_status,
        workpaper_id: workpaper.map(|item| item.workpaper_id.clone()),
        design_conclusion: workpaper.map(|item| item.design_conclusion),
        operating_conclusion: workpaper.map(|item| item.operating_conclusion),
        reviewer_id: workpaper.and_then(|item| {
            item.reviewer_signoff.as_ref().and_then(|signoff| {
                (signoff.conclusion == ReviewConclusion::Approved)
                    .then(|| signoff.reviewer_id.clone())
            })
        }),
        sample_plan_id: workpaper.and_then(|item| item.sample_plan_id.clone()),
        evidence_ids: finding.evidence_ids.clone(),
        exception_ids: workpaper.map_or_else(Vec::new, |item| {
            item.exceptions
                .iter()
                .map(|exception| exception.exception_id.clone())
                .collect()
        }),
        framework_mappings: finding.framework_mappings.clone(),
    }
}

fn evidence_index(
    observations: &[crate::evidence::SealedObservation],
    findings: &[Finding],
) -> Vec<EvidenceIndexEntry> {
    let mut references = BTreeMap::<&str, BTreeSet<String>>::new();
    for finding in findings {
        for evidence_id in &finding.evidence_ids {
            references
                .entry(evidence_id)
                .or_default()
                .insert(finding.rule_id.clone());
        }
    }
    let mut entries = observations
        .iter()
        .map(|observation| EvidenceIndexEntry {
            observation_id: observation.observation_id.clone(),
            external_id: observation.input.external_id.clone(),
            evidence_type: observation.input.evidence_type.clone(),
            subject: observation.input.subject.clone(),
            source_kind: match observation.input.source {
                EvidenceSource::Manual { .. } => "manual",
                EvidenceSource::Connector { .. } => "connector",
                EvidenceSource::RuntimeProbe { .. } => "runtime_probe",
            }
            .to_owned(),
            collected_at: observation.input.collected_at,
            valid_until: observation.input.valid_until,
            facts_sha256: observation.facts_sha256.clone(),
            attested: observation.input.attestation.is_some(),
            referenced_by_rule_ids: references
                .get(observation.observation_id.as_str())
                .map_or_else(Vec::new, |values| values.iter().cloned().collect()),
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| left.observation_id.cmp(&right.observation_id));
    entries
}

fn build_audit_trail(events: &[EngagementEvent]) -> Result<Vec<AuditTrailEntry>, AuditError> {
    let mut previous: Option<String> = None;
    let mut result = Vec::with_capacity(events.len());
    for event in events {
        let entry_sha256 = digest(&("canonical.audit-trail-entry/v1", previous.as_deref(), event))?;
        result.push(AuditTrailEntry {
            event: event.clone(),
            previous_entry_sha256: previous,
            entry_sha256: entry_sha256.clone(),
        });
        previous = Some(entry_sha256);
    }
    Ok(result)
}

fn summarize(
    engagement: &AuditEngagement,
    controls: &[ControlTestResult],
    exceptions: &[ExceptionRecord],
) -> DossierSummary {
    let total_controls = controls.len();
    let satisfactory_controls = count_status(controls, ControlTestStatus::Satisfactory);
    let exception_controls = count_status(controls, ControlTestStatus::Exception);
    let evidence_gap_controls = count_status(controls, ControlTestStatus::EvidenceGap);
    let not_reviewed_controls = count_status(controls, ControlTestStatus::NotReviewed);
    let evidence_covered = controls
        .iter()
        .filter(|item| !item.evidence_ids.is_empty())
        .count();
    let review_covered = controls
        .iter()
        .filter(|item| item.reviewer_id.is_some())
        .count();
    DossierSummary {
        total_controls,
        satisfactory_controls,
        exception_controls,
        evidence_gap_controls,
        not_reviewed_controls,
        evidence_coverage_basis_points: basis_points(evidence_covered, total_controls),
        review_coverage_basis_points: basis_points(review_covered, total_controls),
        open_evidence_requests: engagement
            .evidence_requests
            .iter()
            .filter(|request| {
                !matches!(
                    request.status,
                    RequestStatus::Accepted | RequestStatus::Closed
                )
            })
            .count(),
        total_exceptions: exceptions.len(),
        open_exceptions: exceptions
            .iter()
            .filter(|item| {
                !matches!(
                    item.exception.disposition,
                    ExceptionDisposition::Remediated | ExceptionDisposition::CompensatingControl
                )
            })
            .count(),
        management_responses: exceptions
            .iter()
            .filter(|item| item.management_response.is_some())
            .count(),
    }
}

fn count_status(controls: &[ControlTestResult], status: ControlTestStatus) -> usize {
    controls
        .iter()
        .filter(|item| item.audit_status == status)
        .count()
}

fn basis_points(numerator: usize, denominator: usize) -> u16 {
    if denominator == 0 {
        return 0;
    }
    let value = numerator.saturating_mul(10_000) / denominator;
    u16::try_from(value).unwrap_or(10_000)
}

fn conclude(
    engagement: &AuditEngagement,
    controls: &[ControlTestResult],
    exceptions: &[ExceptionRecord],
) -> AuditConclusion {
    if engagement.phase != EngagementPhase::Finalized
        || controls.iter().any(|item| {
            matches!(
                item.audit_status,
                ControlTestStatus::EvidenceGap | ControlTestStatus::NotReviewed
            )
        })
        || engagement.evidence_requests.iter().any(|request| {
            !matches!(
                request.status,
                RequestStatus::Accepted | RequestStatus::Closed
            )
        })
    {
        return AuditConclusion::Incomplete;
    }
    if controls.iter().any(|item| {
        item.audit_status == ControlTestStatus::Exception && item.severity >= Severity::High
    }) || exceptions.iter().any(|item| {
        item.exception.classification == ExceptionClassification::Major
            && !matches!(
                item.exception.disposition,
                ExceptionDisposition::Remediated | ExceptionDisposition::CompensatingControl
            )
    }) {
        AuditConclusion::Unsatisfactory
    } else if controls
        .iter()
        .any(|item| item.audit_status == ControlTestStatus::Exception)
        || !exceptions.is_empty()
    {
        AuditConclusion::SatisfactoryWithExceptions
    } else {
        AuditConclusion::Satisfactory
    }
}

fn limitations(engagement: &AuditEngagement) -> Vec<String> {
    vec![
        "This dossier records audit-support procedures and tool conclusions; it is not a certification, legal opinion, regulatory determination, or independent auditor report."
            .to_owned(),
        "Only an appropriately authorized and qualified auditor can decide whether procedures, sample sizes, evidence, and conclusions are sufficient for a specific engagement."
            .to_owned(),
        "The evidence index preserves provenance and digests but intentionally excludes normalized fact values and source artifacts."
            .to_owned(),
        "Framework mappings are directional aids and do not replace authoritative source material or licensed standards."
            .to_owned(),
        format!(
            "The dossier reflects engagement {} at the {:?} phase and must be regenerated when its record changes.",
            engagement.engagement_id, engagement.phase
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basis_points_are_bounded() {
        assert_eq!(basis_points(0, 0), 0);
        assert_eq!(basis_points(1, 4), 2_500);
        assert_eq!(basis_points(4, 4), 10_000);
    }
}
