//! Normalization boundary for read-only external scanner reports.
//!
//! The MCP readiness scanner and other approved collectors can execute third-party
//! tools, but the deterministic auditor must not trust or preserve their raw output.
//! This module accepts the small normalized report envelope, verifies the scan was
//! explicitly read-only, and turns it into bounded framework-neutral observations.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::{Value, json};

use crate::AuditError;
use crate::evidence::digest;
use crate::model::{EVIDENCE_SCHEMA, EvidenceBundle, EvidenceObservation, EvidenceSource};

const MAX_REPORT_BYTES: usize = 2 * 1024 * 1024;
const MAX_FINDINGS: usize = 100;
const MAX_TEXT_BYTES: usize = 4 * 1024;
const MAX_VALIDITY_SECONDS: i64 = 30 * 24 * 60 * 60;

const APPROVED_TOOLS: &[&str] = &[
    "prowler",
    "scout-suite",
    "trivy",
    "checkov",
    "kubescape",
    "kube-bench",
    "kubeaudit",
    "infracost",
    "powerpipe",
];

/// Minimal normalized report emitted by the read-only external-tool runner.
///
/// Fields such as command-line arguments and stderr are intentionally omitted from
/// this boundary. Serde ignores those extra fields, which prevents them from becoming
/// durable evidence while allowing the transport envelope to evolve independently.
#[derive(Debug, Deserialize)]
struct ExternalScanReport {
    tool: String,
    provider: Option<String>,
    status: String,
    read_only: bool,
    exit_code: Option<i32>,
    #[serde(default)]
    counts: ExternalCounts,
    #[serde(default)]
    findings: Vec<ExternalFinding>,
}

#[derive(Debug, Default, Deserialize)]
struct ExternalCounts {
    #[serde(default)]
    passed: usize,
    #[serde(default)]
    failed: usize,
    #[serde(default)]
    warning: usize,
    #[serde(default)]
    skipped: usize,
    #[serde(default)]
    informational: usize,
    #[serde(default)]
    total_records: usize,
}

#[derive(Debug, Deserialize)]
struct ExternalFinding {
    id: String,
    severity: String,
    title: String,
    detail: String,
    resource: Option<String>,
}

/// Convert one normalized third-party scanner report into a validated evidence bundle.
///
/// The returned observations preserve the scanner identity and normalized facts while
/// deliberately dropping raw stdout/stderr, executable paths, arguments, credentials,
/// and tool-authored remediation prose. At least one `scanner.run` observation is
/// always emitted, even when the scanner found no problems.
///
/// # Errors
///
/// Returns [`AuditError`] when the report is oversized or malformed, the scanner is not
/// approved, the report is not explicitly read-only, timestamps are invalid, or the
/// resulting evidence bundle violates the auditor's normal tenant/scope invariants.
pub fn external_scan_to_evidence(
    tenant_id: &str,
    scope_id: &str,
    collected_at: i64,
    valid_for_seconds: i64,
    adapter_version: &str,
    report_json: &[u8],
) -> Result<EvidenceBundle, AuditError> {
    if report_json.len() > MAX_REPORT_BYTES {
        return Err(AuditError::Invalid {
            field: "externalScanReport",
            reason: format!("may contain at most {MAX_REPORT_BYTES} bytes"),
        });
    }
    if collected_at < 0 || !(1..=MAX_VALIDITY_SECONDS).contains(&valid_for_seconds) {
        return Err(AuditError::Invalid {
            field: "externalScanFreshness",
            reason: format!(
                "requires collectedAt >= 0 and validForSeconds in 1..={MAX_VALIDITY_SECONDS}"
            ),
        });
    }
    let valid_until =
        collected_at
            .checked_add(valid_for_seconds)
            .ok_or_else(|| AuditError::Invalid {
                field: "externalScanFreshness",
                reason: "validUntil overflowed".to_owned(),
            })?;

    let report: ExternalScanReport = serde_json::from_slice(report_json)?;
    if !APPROVED_TOOLS.contains(&report.tool.as_str()) {
        return Err(AuditError::Invalid {
            field: "externalScanner",
            reason: "scanner is not in the approved external-tool catalog".to_owned(),
        });
    }
    if !report.read_only {
        return Err(AuditError::Invalid {
            field: "externalScanner",
            reason: "scanner report must explicitly attest readOnly=true".to_owned(),
        });
    }
    if !matches!(
        report.status.as_str(),
        "completed" | "completed-with-nonzero-exit"
    ) {
        return Err(AuditError::Invalid {
            field: "externalScannerStatus",
            reason: "scanner status is not a completed state".to_owned(),
        });
    }
    if report.findings.len() > MAX_FINDINGS {
        return Err(AuditError::Invalid {
            field: "externalScannerFindings",
            reason: format!("may contain at most {MAX_FINDINGS} normalized findings"),
        });
    }
    if report
        .provider
        .as_deref()
        .is_some_and(|value| value.len() > 160)
    {
        return Err(AuditError::Invalid {
            field: "externalScannerProvider",
            reason: "provider label is too long".to_owned(),
        });
    }

    let source = EvidenceSource::Connector {
        connector: format!("external.{}", report.tool),
        adapter_version: adapter_version.to_owned(),
    };

    let mut observations = Vec::with_capacity(report.findings.len() + 1);
    let mut run_facts = BTreeMap::from([
        ("tool".to_owned(), json!(report.tool.clone())),
        ("status".to_owned(), json!(report.status.clone())),
        ("readOnly".to_owned(), json!(true)),
        ("passed".to_owned(), json!(report.counts.passed)),
        ("failed".to_owned(), json!(report.counts.failed)),
        ("warning".to_owned(), json!(report.counts.warning)),
        ("skipped".to_owned(), json!(report.counts.skipped)),
        (
            "informational".to_owned(),
            json!(report.counts.informational),
        ),
        (
            "totalRecords".to_owned(),
            json!(report.counts.total_records),
        ),
    ]);
    if let Some(provider) = report.provider.as_deref() {
        run_facts.insert("provider".to_owned(), json!(provider));
    }
    if let Some(exit_code) = report.exit_code {
        run_facts.insert("exitCode".to_owned(), json!(exit_code));
    }
    let run_external_id = digest(&(
        "canonical.external-scanner-run/v1",
        tenant_id,
        scope_id,
        collected_at,
        &report.tool,
        &report.provider,
        &report.status,
        report.counts.total_records,
    ))?;
    observations.push(EvidenceObservation {
        external_id: run_external_id,
        evidence_type: "scanner.run".to_owned(),
        subject: scope_id.to_owned(),
        source: source.clone(),
        collected_at,
        valid_until,
        facts: run_facts,
        attestation: None,
    });

    for finding in report.findings {
        validate_finding(&finding)?;
        let finding_external_id = digest(&(
            "canonical.external-scanner-finding/v1",
            tenant_id,
            scope_id,
            collected_at,
            &report.tool,
            &report.provider,
            &finding.id,
            &finding.severity,
            &finding.title,
            &finding.resource,
        ))?;
        let mut facts = BTreeMap::<String, Value>::from([
            ("tool".to_owned(), json!(report.tool.clone())),
            ("scannerFindingId".to_owned(), json!(finding.id.clone())),
            ("severity".to_owned(), json!(finding.severity.clone())),
            ("title".to_owned(), json!(finding.title.clone())),
            ("detail".to_owned(), json!(finding.detail.clone())),
        ]);
        if let Some(provider) = report.provider.as_deref() {
            facts.insert("provider".to_owned(), json!(provider));
        }
        if let Some(resource) = finding.resource.as_deref() {
            facts.insert("resource".to_owned(), json!(resource));
        }
        observations.push(EvidenceObservation {
            external_id: finding_external_id,
            evidence_type: "scanner.finding".to_owned(),
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

fn validate_finding(finding: &ExternalFinding) -> Result<(), AuditError> {
    for (field, value) in [
        ("externalFindingId", finding.id.as_str()),
        ("externalFindingSeverity", finding.severity.as_str()),
        ("externalFindingTitle", finding.title.as_str()),
        ("externalFindingDetail", finding.detail.as_str()),
    ] {
        if value.is_empty() || value.len() > MAX_TEXT_BYTES {
            return Err(AuditError::Invalid {
                field,
                reason: format!("must contain 1..={MAX_TEXT_BYTES} bytes"),
            });
        }
    }
    if finding
        .resource
        .as_deref()
        .is_some_and(|value| value.len() > MAX_TEXT_BYTES)
    {
        return Err(AuditError::Invalid {
            field: "externalFindingResource",
            reason: format!("may contain at most {MAX_TEXT_BYTES} bytes"),
        });
    }
    if !matches!(
        finding.severity.as_str(),
        "critical" | "high" | "medium" | "low" | "info"
    ) {
        return Err(AuditError::Invalid {
            field: "externalFindingSeverity",
            reason: "must be critical, high, medium, low, or info".to_owned(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(read_only: bool, findings: &str) -> Vec<u8> {
        format!(
            r#"{{
                "tool":"prowler",
                "provider":"aws",
                "status":"completed",
                "read_only":{read_only},
                "executable":"/usr/local/bin/prowler",
                "arguments":["aws","--output-formats","json-ocsf"],
                "exit_code":0,
                "counts":{{"passed":10,"failed":1,"warning":0,"skipped":2,"informational":0,"total_records":13}},
                "findings":{findings},
                "notes":["raw scanner note must not become durable evidence"]
            }}"#
        )
        .into_bytes()
    }

    #[test]
    fn converts_normalized_findings_without_persisting_command_metadata() -> Result<(), AuditError>
    {
        let input = report(
            true,
            r#"[{"id":"prowler.iam.1","severity":"high","title":"MFA missing","detail":"One principal has no MFA","resource":"arn:aws:iam::123:user/alice"}]"#,
        );
        let bundle = external_scan_to_evidence(
            "tenant-a",
            "organization/acme",
            1_700_000_000,
            3_600,
            "canonical-mcp-server.rs@1",
            &input,
        )?;
        assert_eq!(bundle.observations.len(), 2);
        bundle.validate()?;
        let encoded = serde_json::to_string(&bundle)?;
        assert!(!encoded.contains("/usr/local/bin/prowler"));
        assert!(!encoded.contains("--output-formats"));
        assert!(!encoded.contains("raw scanner note"));
        assert!(encoded.contains("external.prowler"));
        assert!(encoded.contains("scanner.finding"));
        Ok(())
    }

    #[test]
    fn emits_run_evidence_when_scanner_has_no_findings() -> Result<(), AuditError> {
        let bundle = external_scan_to_evidence(
            "tenant-a",
            "organization/acme",
            1_700_000_000,
            300,
            "canonical-mcp-server.rs@1",
            &report(true, "[]"),
        )?;
        assert_eq!(bundle.observations.len(), 1);
        assert_eq!(bundle.observations[0].evidence_type, "scanner.run");
        Ok(())
    }

    #[test]
    fn rejects_any_report_not_explicitly_read_only() {
        let result = external_scan_to_evidence(
            "tenant-a",
            "organization/acme",
            1_700_000_000,
            300,
            "canonical-mcp-server.rs@1",
            &report(false, "[]"),
        );
        assert!(result.is_err());
    }

    #[test]
    fn rejects_unapproved_scanner_identity() {
        let fixture = report(true, "[]");
        let text = String::from_utf8_lossy(&fixture);
        let input = text
            .replace("\"prowler\"", "\"arbitrary-tool\"")
            .into_bytes();
        let result = external_scan_to_evidence(
            "tenant-a",
            "organization/acme",
            1_700_000_000,
            300,
            "canonical-mcp-server.rs@1",
            &input,
        );
        assert!(result.is_err());
    }
}
