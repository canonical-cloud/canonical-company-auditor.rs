//! Framework-neutral evidence normalization for operational readiness reports.
//!
//! Prometheus and `OpenCost` provide runtime and cost-allocation observations that complement
//! provider inventory scans. Their scanner-authored recommendations and free-form notes are
//! intentionally excluded from durable audit evidence; deterministic Canonical rules decide
//! later whether any observed signal maps to a framework control.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::{Value, json};

use crate::AuditError;
use crate::evidence::digest;
use crate::model::{EVIDENCE_SCHEMA, EvidenceBundle, EvidenceObservation, EvidenceSource};

const MAX_REPORT_BYTES: usize = 2 * 1024 * 1024;
const MAX_EVIDENCE: usize = 256;
const MAX_FINDINGS: usize = 512;
const MAX_TEXT_BYTES: usize = 4 * 1024;
const MAX_VALIDITY_SECONDS: i64 = 24 * 60 * 60;

#[derive(Debug, Deserialize)]
struct OperationalReport {
    prometheus: String,
    opencost: String,
    thresholds: Thresholds,
    #[serde(default)]
    evidence: Vec<OperationalEvidence>,
    #[serde(default)]
    findings: Vec<OperationalFinding>,
}

#[derive(Debug, Deserialize)]
struct Thresholds {
    #[serde(rename = "cpu_high_percent")]
    cpu_high: f64,
    #[serde(rename = "disk_free_low_percent")]
    disk_free_low: f64,
    #[serde(rename = "memory_free_low_percent")]
    memory_free_low: f64,
}

#[derive(Debug, Deserialize)]
struct OperationalEvidence {
    source: String,
    check: String,
    status: String,
    summary: String,
}

#[derive(Debug, Deserialize)]
struct OperationalFinding {
    id: String,
    severity: String,
    category: String,
    title: String,
    detail: String,
    #[serde(default)]
    resource: Option<String>,
}

#[derive(Clone, Copy)]
struct EvidenceContext<'a> {
    tenant_id: &'a str,
    scope_id: &'a str,
    collected_at: i64,
    valid_until: i64,
}

/// Convert one read-only Prometheus/`OpenCost` operational report into evidence.
///
/// The source report may contain scanner notes and remediation recommendations, but this
/// adapter's narrow deserialization surface drops them. The resulting observations preserve
/// only bounded status, threshold, check, finding, and resource facts.
///
/// # Errors
///
/// Returns [`AuditError`] for malformed or oversized reports, invalid thresholds, unexpected
/// evidence sources, invalid freshness, excessive records, or unsafe normalized text.
pub fn operational_readiness_to_evidence(
    tenant_id: &str,
    scope_id: &str,
    collected_at: i64,
    valid_for_seconds: i64,
    adapter_version: &str,
    report_json: &[u8],
) -> Result<EvidenceBundle, AuditError> {
    let (report, valid_until) = parse_report(report_json, collected_at, valid_for_seconds)?;
    let context = EvidenceContext {
        tenant_id,
        scope_id,
        collected_at,
        valid_until,
    };
    let source = EvidenceSource::Connector {
        connector: "canonical-operational-readiness".to_owned(),
        adapter_version: adapter_version.to_owned(),
    };
    let mut observations = Vec::with_capacity(1 + report.evidence.len() + report.findings.len());
    observations.push(run_observation(context, &source, &report)?);
    for evidence in &report.evidence {
        observations.push(check_observation(context, &source, evidence)?);
    }
    for finding in &report.findings {
        observations.push(finding_observation(context, &source, finding)?);
    }

    let bundle = EvidenceBundle {
        schema_version: EVIDENCE_SCHEMA.to_owned(),
        tenant_id: tenant_id.to_owned(),
        scope_id: scope_id.to_owned(),
        observations,
    };
    bundle.validate()?;
    Ok(bundle)
}

fn parse_report(
    report_json: &[u8],
    collected_at: i64,
    valid_for_seconds: i64,
) -> Result<(OperationalReport, i64), AuditError> {
    if report_json.len() > MAX_REPORT_BYTES {
        return Err(AuditError::Invalid {
            field: "operationalReadinessReport",
            reason: format!("may contain at most {MAX_REPORT_BYTES} bytes"),
        });
    }
    if collected_at < 0 || !(1..=MAX_VALIDITY_SECONDS).contains(&valid_for_seconds) {
        return Err(AuditError::Invalid {
            field: "operationalReadinessFreshness",
            reason: format!(
                "requires collectedAt >= 0 and validForSeconds in 1..={MAX_VALIDITY_SECONDS}"
            ),
        });
    }
    let valid_until =
        collected_at
            .checked_add(valid_for_seconds)
            .ok_or_else(|| AuditError::Invalid {
                field: "operationalReadinessFreshness",
                reason: "validUntil overflowed".to_owned(),
            })?;
    let report: OperationalReport = serde_json::from_slice(report_json)?;
    validate_report(&report)?;
    Ok((report, valid_until))
}

fn validate_report(report: &OperationalReport) -> Result<(), AuditError> {
    validate_text("prometheusStatus", &report.prometheus)?;
    validate_text("openCostStatus", &report.opencost)?;
    validate_thresholds(&report.thresholds)?;
    if report.evidence.len() > MAX_EVIDENCE || report.findings.len() > MAX_FINDINGS {
        return Err(AuditError::Invalid {
            field: "operationalReadinessRecords",
            reason: "report contains too many evidence rows or findings".to_owned(),
        });
    }
    Ok(())
}

fn run_observation(
    context: EvidenceContext<'_>,
    source: &EvidenceSource,
    report: &OperationalReport,
) -> Result<EvidenceObservation, AuditError> {
    let external_id = digest(&(
        "canonical.operational-readiness-run/v1",
        context.tenant_id,
        context.scope_id,
        context.collected_at,
        &report.prometheus,
        &report.opencost,
        report.thresholds.cpu_high.to_bits(),
        report.thresholds.disk_free_low.to_bits(),
        report.thresholds.memory_free_low.to_bits(),
    ))?;
    Ok(EvidenceObservation {
        external_id,
        evidence_type: "operations.readiness_run".to_owned(),
        subject: context.scope_id.to_owned(),
        source: source.clone(),
        collected_at: context.collected_at,
        valid_until: context.valid_until,
        facts: BTreeMap::<String, Value>::from([
            ("prometheusStatus".to_owned(), json!(report.prometheus)),
            ("openCostStatus".to_owned(), json!(report.opencost)),
            (
                "cpuHighPercent".to_owned(),
                json!(report.thresholds.cpu_high),
            ),
            (
                "diskFreeLowPercent".to_owned(),
                json!(report.thresholds.disk_free_low),
            ),
            (
                "memoryFreeLowPercent".to_owned(),
                json!(report.thresholds.memory_free_low),
            ),
        ]),
        attestation: None,
    })
}

fn check_observation(
    context: EvidenceContext<'_>,
    source: &EvidenceSource,
    evidence: &OperationalEvidence,
) -> Result<EvidenceObservation, AuditError> {
    validate_operational_evidence(evidence)?;
    let external_id = digest(&(
        "canonical.operational-readiness-evidence/v1",
        context.tenant_id,
        context.scope_id,
        context.collected_at,
        &evidence.source,
        &evidence.check,
        &evidence.status,
        &evidence.summary,
    ))?;
    Ok(EvidenceObservation {
        external_id,
        evidence_type: "operations.check".to_owned(),
        subject: context.scope_id.to_owned(),
        source: source.clone(),
        collected_at: context.collected_at,
        valid_until: context.valid_until,
        facts: BTreeMap::<String, Value>::from([
            ("source".to_owned(), json!(evidence.source.clone())),
            ("check".to_owned(), json!(evidence.check.clone())),
            ("status".to_owned(), json!(evidence.status.clone())),
            ("summary".to_owned(), json!(evidence.summary.clone())),
        ]),
        attestation: None,
    })
}

fn finding_observation(
    context: EvidenceContext<'_>,
    source: &EvidenceSource,
    finding: &OperationalFinding,
) -> Result<EvidenceObservation, AuditError> {
    validate_operational_finding(finding)?;
    let external_id = digest(&(
        "canonical.operational-readiness-finding/v1",
        context.tenant_id,
        context.scope_id,
        context.collected_at,
        &finding.id,
        &finding.severity,
        &finding.category,
        &finding.resource,
    ))?;
    let mut facts = BTreeMap::<String, Value>::from([
        ("scannerFindingId".to_owned(), json!(finding.id.clone())),
        ("severity".to_owned(), json!(finding.severity.clone())),
        ("category".to_owned(), json!(finding.category.clone())),
        ("title".to_owned(), json!(finding.title.clone())),
        ("detail".to_owned(), json!(finding.detail.clone())),
    ]);
    if let Some(resource) = finding.resource.as_deref() {
        facts.insert("resource".to_owned(), json!(resource));
    }
    Ok(EvidenceObservation {
        external_id,
        evidence_type: "operations.finding".to_owned(),
        subject: context.scope_id.to_owned(),
        source: source.clone(),
        collected_at: context.collected_at,
        valid_until: context.valid_until,
        facts,
        attestation: None,
    })
}

fn validate_thresholds(thresholds: &Thresholds) -> Result<(), AuditError> {
    for (field, value) in [
        ("cpuHighPercent", thresholds.cpu_high),
        ("diskFreeLowPercent", thresholds.disk_free_low),
        ("memoryFreeLowPercent", thresholds.memory_free_low),
    ] {
        if !value.is_finite() || !(0.0..=100.0).contains(&value) {
            return Err(AuditError::Invalid {
                field: "operationalReadinessThresholds",
                reason: format!("{field} must be a finite percentage in 0..=100"),
            });
        }
    }
    Ok(())
}

fn validate_operational_evidence(evidence: &OperationalEvidence) -> Result<(), AuditError> {
    if !matches!(evidence.source.as_str(), "prometheus" | "opencost") {
        return Err(AuditError::Invalid {
            field: "operationalReadinessSource",
            reason: "source must be prometheus or opencost".to_owned(),
        });
    }
    validate_text("operationalReadinessCheck", &evidence.check)?;
    validate_text("operationalReadinessStatus", &evidence.status)?;
    validate_text("operationalReadinessSummary", &evidence.summary)
}

fn validate_operational_finding(finding: &OperationalFinding) -> Result<(), AuditError> {
    for (field, value) in [
        ("operationalFindingId", finding.id.as_str()),
        ("operationalFindingSeverity", finding.severity.as_str()),
        ("operationalFindingCategory", finding.category.as_str()),
        ("operationalFindingTitle", finding.title.as_str()),
        ("operationalFindingDetail", finding.detail.as_str()),
    ] {
        validate_text(field, value)?;
    }
    if !matches!(
        finding.severity.as_str(),
        "critical" | "high" | "medium" | "low" | "info"
    ) {
        return Err(AuditError::Invalid {
            field: "operationalFindingSeverity",
            reason: "must be critical, high, medium, low, or info".to_owned(),
        });
    }
    if let Some(resource) = finding.resource.as_deref() {
        validate_text("operationalFindingResource", resource)?;
    }
    Ok(())
}

fn validate_text(field: &'static str, value: &str) -> Result<(), AuditError> {
    if value.is_empty()
        || value.len() > MAX_TEXT_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(AuditError::Invalid {
            field,
            reason: format!("must be trimmed printable text containing 1..={MAX_TEXT_BYTES} bytes"),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report() -> Vec<u8> {
        br#"{
            "prometheus":"configured",
            "opencost":"configured",
            "thresholds":{"cpu_high_percent":85.0,"disk_free_low_percent":15.0,"memory_free_low_percent":15.0},
            "evidence":[{"source":"prometheus","check":"cpu-utilization","status":"observed","summary":"3 host CPU series inspected"}],
            "findings":[{"id":"prometheus.cpu.node-a","severity":"high","category":"utilization-and-capacity","title":"High CPU utilization","detail":"node-a reports 94 percent CPU","recommendation":"scale the workload","resource":"node-a"}],
            "notes":["free-form scanner note"]
        }"#
        .to_vec()
    }

    #[test]
    fn converts_operational_report_without_remediation_prose() -> Result<(), AuditError> {
        let bundle = operational_readiness_to_evidence(
            "tenant-a",
            "organization/acme",
            1_700_000_000,
            300,
            "canonical-mcp-server.rs@1",
            &report(),
        )?;
        assert_eq!(bundle.observations.len(), 3);
        let encoded = serde_json::to_string(&bundle)?;
        assert!(!encoded.contains("scale the workload"));
        assert!(!encoded.contains("free-form scanner note"));
        assert!(encoded.contains("operations.check"));
        assert!(encoded.contains("operations.finding"));
        Ok(())
    }

    #[test]
    fn rejects_unknown_evidence_source() {
        let fixture = report();
        let text = String::from_utf8_lossy(&fixture);
        let input = text.replace("\"prometheus\"", "\"arbitrary\"").into_bytes();
        assert!(
            operational_readiness_to_evidence(
                "tenant-a",
                "organization/acme",
                1_700_000_000,
                300,
                "mcp@1",
                &input,
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_non_finite_or_out_of_range_thresholds() {
        let fixture = report();
        let text = String::from_utf8_lossy(&fixture);
        let input = text.replace("85.0", "101.0").into_bytes();
        assert!(
            operational_readiness_to_evidence(
                "tenant-a",
                "organization/acme",
                1_700_000_000,
                300,
                "mcp@1",
                &input,
            )
            .is_err()
        );
    }
}
