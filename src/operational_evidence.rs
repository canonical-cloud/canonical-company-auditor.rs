//! Framework-neutral evidence normalization for operational readiness reports.
//!
//! Prometheus and OpenCost provide runtime and cost-allocation observations that complement
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
    cpu_high_percent: f64,
    disk_free_low_percent: f64,
    memory_free_low_percent: f64,
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

/// Convert one read-only Prometheus/OpenCost operational report into evidence.
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
    validate_text("prometheusStatus", &report.prometheus)?;
    validate_text("openCostStatus", &report.opencost)?;
    validate_thresholds(&report.thresholds)?;
    if report.evidence.len() > MAX_EVIDENCE || report.findings.len() > MAX_FINDINGS {
        return Err(AuditError::Invalid {
            field: "operationalReadinessRecords",
            reason: "report contains too many evidence rows or findings".to_owned(),
        });
    }

    let source = EvidenceSource::Connector {
        connector: "canonical-operational-readiness".to_owned(),
        adapter_version: adapter_version.to_owned(),
    };
    let mut observations = Vec::with_capacity(1 + report.evidence.len() + report.findings.len());
    let run_external_id = digest(&(
        "canonical.operational-readiness-run/v1",
        tenant_id,
        scope_id,
        collected_at,
        &report.prometheus,
        &report.opencost,
        report.thresholds.cpu_high_percent.to_bits(),
        report.thresholds.disk_free_low_percent.to_bits(),
        report.thresholds.memory_free_low_percent.to_bits(),
    ))?;
    observations.push(EvidenceObservation {
        external_id: run_external_id,
        evidence_type: "operations.readiness_run".to_owned(),
        subject: scope_id.to_owned(),
        source: source.clone(),
        collected_at,
        valid_until,
        facts: BTreeMap::<String, Value>::from([
            ("prometheusStatus".to_owned(), json!(report.prometheus)),
            ("openCostStatus".to_owned(), json!(report.opencost)),
            (
                "cpuHighPercent".to_owned(),
                json!(report.thresholds.cpu_high_percent),
            ),
            (
                "diskFreeLowPercent".to_owned(),
                json!(report.thresholds.disk_free_low_percent),
            ),
            (
                "memoryFreeLowPercent".to_owned(),
                json!(report.thresholds.memory_free_low_percent),
            ),
        ]),
        attestation: None,
    });

    for evidence in report.evidence {
        validate_operational_evidence(&evidence)?;
        let external_id = digest(&(
            "canonical.operational-readiness-evidence/v1",
            tenant_id,
            scope_id,
            collected_at,
            &evidence.source,
            &evidence.check,
            &evidence.status,
            &evidence.summary,
        ))?;
        observations.push(EvidenceObservation {
            external_id,
            evidence_type: "operations.check".to_owned(),
            subject: scope_id.to_owned(),
            source: source.clone(),
            collected_at,
            valid_until,
            facts: BTreeMap::<String, Value>::from([
                ("source".to_owned(), json!(evidence.source)),
                ("check".to_owned(), json!(evidence.check)),
                ("status".to_owned(), json!(evidence.status)),
                ("summary".to_owned(), json!(evidence.summary)),
            ]),
            attestation: None,
        });
    }

    for finding in report.findings {
        validate_operational_finding(&finding)?;
        let external_id = digest(&(
            "canonical.operational-readiness-finding/v1",
            tenant_id,
            scope_id,
            collected_at,
            &finding.id,
            &finding.severity,
            &finding.category,
            &finding.resource,
        ))?;
        let mut facts = BTreeMap::<String, Value>::from([
            ("scannerFindingId".to_owned(), json!(finding.id)),
            ("severity".to_owned(), json!(finding.severity)),
            ("category".to_owned(), json!(finding.category)),
            ("title".to_owned(), json!(finding.title)),
            ("detail".to_owned(), json!(finding.detail)),
        ]);
        if let Some(resource) = finding.resource {
            facts.insert("resource".to_owned(), json!(resource));
        }
        observations.push(EvidenceObservation {
            external_id,
            evidence_type: "operations.finding".to_owned(),
            subject: scope_id.to_owned(),
            source: source.clone(),
            collected_at,
            valid_until,
            facts,
            attestation: None,
        });
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

fn validate_thresholds(thresholds: &Thresholds) -> Result<(), AuditError> {
    for (field, value) in [
        ("cpuHighPercent", thresholds.cpu_high_percent),
        ("diskFreeLowPercent", thresholds.disk_free_low_percent),
        ("memoryFreeLowPercent", thresholds.memory_free_low_percent),
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
