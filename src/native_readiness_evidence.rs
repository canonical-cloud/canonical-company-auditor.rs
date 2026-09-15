//! Evidence normalization for Canonical's native read-only provider readiness scanner.
//!
//! The native MCP scanner is useful collection infrastructure, but its scores and prose are
//! not themselves compliance conclusions. This boundary preserves bounded observed facts and
//! finding signals while dropping scanner notes and remediation text before deterministic
//! audit rules consume the evidence.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::{Value, json};

use crate::AuditError;
use crate::evidence::digest;
use crate::model::{EVIDENCE_SCHEMA, EvidenceBundle, EvidenceObservation, EvidenceSource};

const MAX_REPORT_BYTES: usize = 2 * 1024 * 1024;
const MAX_FINDINGS: usize = 512;
const MAX_CHECKS: usize = 128;
const MAX_TEXT_BYTES: usize = 4 * 1024;
const MAX_VALIDITY_SECONDS: i64 = 30 * 24 * 60 * 60;

const PROVIDERS: &[&str] = &[
    "aws",
    "gcp",
    "azure",
    "cloudflare",
    "github",
    "upstash",
    "vercel",
    "digital-ocean",
    "netlify",
    "render",
    "fly-io",
    "heroku",
];

#[derive(Debug, Deserialize)]
struct NativeScanReport {
    provider: String,
    scope: Option<String>,
    transport: String,
    auth_status: String,
    score: u8,
    #[serde(default)]
    checks: Vec<NativeCheck>,
    #[serde(default)]
    findings: Vec<NativeFinding>,
}

#[derive(Debug, Deserialize)]
struct NativeCheck {
    check: String,
    status: String,
    summary: String,
}

#[derive(Debug, Deserialize)]
struct NativeFinding {
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

/// Convert a Canonical native account-readiness report into framework-neutral evidence.
///
/// The caller supplies the authoritative audit tenant/scope and collection timestamp. A
/// scanner-specific scope is retained only as a fact because cloud account/project labels are
/// not the same namespace as Canonical's tenant hierarchy.
///
/// # Errors
///
/// Fails closed for oversized/malformed reports, unknown providers, unexpected transport
/// families, invalid freshness, excessive record counts, or unsafe normalized text.
pub fn native_readiness_to_evidence(
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
        connector: format!("canonical-readiness.{}", report.provider),
        adapter_version: adapter_version.to_owned(),
    };
    let mut observations = Vec::with_capacity(1 + report.checks.len() + report.findings.len());
    observations.push(run_observation(context, &source, &report)?);
    for check in &report.checks {
        observations.push(check_observation(context, &source, &report, check)?);
    }
    for finding in &report.findings {
        observations.push(finding_observation(context, &source, &report, finding)?);
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
) -> Result<(NativeScanReport, i64), AuditError> {
    if report_json.len() > MAX_REPORT_BYTES {
        return Err(AuditError::Invalid {
            field: "nativeReadinessReport",
            reason: format!("may contain at most {MAX_REPORT_BYTES} bytes"),
        });
    }
    if collected_at < 0 || !(1..=MAX_VALIDITY_SECONDS).contains(&valid_for_seconds) {
        return Err(AuditError::Invalid {
            field: "nativeReadinessFreshness",
            reason: format!(
                "requires collectedAt >= 0 and validForSeconds in 1..={MAX_VALIDITY_SECONDS}"
            ),
        });
    }
    let valid_until =
        collected_at
            .checked_add(valid_for_seconds)
            .ok_or_else(|| AuditError::Invalid {
                field: "nativeReadinessFreshness",
                reason: "validUntil overflowed".to_owned(),
            })?;
    let report: NativeScanReport = serde_json::from_slice(report_json)?;
    validate_report(&report)?;
    Ok((report, valid_until))
}

fn validate_report(report: &NativeScanReport) -> Result<(), AuditError> {
    if !PROVIDERS.contains(&report.provider.as_str()) {
        return Err(AuditError::Invalid {
            field: "nativeReadinessProvider",
            reason: "provider is not in the native readiness catalog".to_owned(),
        });
    }
    validate_transport(&report.transport)?;
    validate_text("nativeReadinessAuthStatus", &report.auth_status)?;
    if report.findings.len() > MAX_FINDINGS || report.checks.len() > MAX_CHECKS {
        return Err(AuditError::Invalid {
            field: "nativeReadinessRecords",
            reason: "report contains too many checks or findings".to_owned(),
        });
    }
    if report.scope.as_deref().is_some_and(|value| {
        value.is_empty() || value.len() > 200 || value.chars().any(char::is_control)
    }) {
        return Err(AuditError::Invalid {
            field: "nativeReadinessScope",
            reason: "provider scope must be bounded printable text".to_owned(),
        });
    }
    Ok(())
}

fn run_observation(
    context: EvidenceContext<'_>,
    source: &EvidenceSource,
    report: &NativeScanReport,
) -> Result<EvidenceObservation, AuditError> {
    let mut facts = BTreeMap::from([
        ("provider".to_owned(), json!(report.provider.clone())),
        ("transport".to_owned(), json!(report.transport.clone())),
        ("authStatus".to_owned(), json!(report.auth_status.clone())),
        ("scannerScore".to_owned(), json!(report.score)),
    ]);
    if let Some(provider_scope) = report.scope.as_deref() {
        facts.insert("providerScope".to_owned(), json!(provider_scope));
    }
    let external_id = digest(&(
        "canonical.native-readiness-run/v1",
        context.tenant_id,
        context.scope_id,
        context.collected_at,
        &report.provider,
        &report.scope,
        &report.transport,
    ))?;
    Ok(EvidenceObservation {
        external_id,
        evidence_type: "readiness.run".to_owned(),
        subject: context.scope_id.to_owned(),
        source: source.clone(),
        collected_at: context.collected_at,
        valid_until: context.valid_until,
        facts,
        attestation: None,
    })
}

fn check_observation(
    context: EvidenceContext<'_>,
    source: &EvidenceSource,
    report: &NativeScanReport,
    check: &NativeCheck,
) -> Result<EvidenceObservation, AuditError> {
    validate_text("nativeReadinessCheck", &check.check)?;
    validate_text("nativeReadinessCheckStatus", &check.status)?;
    validate_text("nativeReadinessCheckSummary", &check.summary)?;
    let external_id = digest(&(
        "canonical.native-readiness-check/v1",
        context.tenant_id,
        context.scope_id,
        context.collected_at,
        &report.provider,
        &check.check,
        &check.status,
        &check.summary,
    ))?;
    Ok(EvidenceObservation {
        external_id,
        evidence_type: "readiness.check".to_owned(),
        subject: context.scope_id.to_owned(),
        source: source.clone(),
        collected_at: context.collected_at,
        valid_until: context.valid_until,
        facts: BTreeMap::<String, Value>::from([
            ("provider".to_owned(), json!(report.provider.clone())),
            ("check".to_owned(), json!(check.check.clone())),
            ("status".to_owned(), json!(check.status.clone())),
            ("summary".to_owned(), json!(check.summary.clone())),
        ]),
        attestation: None,
    })
}

fn finding_observation(
    context: EvidenceContext<'_>,
    source: &EvidenceSource,
    report: &NativeScanReport,
    finding: &NativeFinding,
) -> Result<EvidenceObservation, AuditError> {
    validate_finding(finding)?;
    let external_id = digest(&(
        "canonical.native-readiness-finding/v1",
        context.tenant_id,
        context.scope_id,
        context.collected_at,
        &report.provider,
        &finding.id,
        &finding.severity,
        &finding.category,
        &finding.resource,
    ))?;
    let mut facts = BTreeMap::<String, Value>::from([
        ("provider".to_owned(), json!(report.provider.clone())),
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
        evidence_type: "readiness.finding".to_owned(),
        subject: context.scope_id.to_owned(),
        source: source.clone(),
        collected_at: context.collected_at,
        valid_until: context.valid_until,
        facts,
        attestation: None,
    })
}

fn validate_transport(value: &str) -> Result<(), AuditError> {
    if matches!(
        value,
        "HTTPS GET only"
            | "allowlisted aws CLI API calls"
            | "allowlisted gcloud API calls"
            | "allowlisted az CLI API calls"
            | "allowlisted flyctl read calls"
    ) {
        Ok(())
    } else {
        Err(AuditError::Invalid {
            field: "nativeReadinessTransport",
            reason: "transport is not a recognized read-only native adapter".to_owned(),
        })
    }
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

fn validate_finding(finding: &NativeFinding) -> Result<(), AuditError> {
    for (field, value) in [
        ("nativeReadinessFindingId", finding.id.as_str()),
        ("nativeReadinessFindingSeverity", finding.severity.as_str()),
        ("nativeReadinessFindingCategory", finding.category.as_str()),
        ("nativeReadinessFindingTitle", finding.title.as_str()),
        ("nativeReadinessFindingDetail", finding.detail.as_str()),
    ] {
        validate_text(field, value)?;
    }
    if !matches!(
        finding.severity.as_str(),
        "critical" | "high" | "medium" | "low" | "info"
    ) {
        return Err(AuditError::Invalid {
            field: "nativeReadinessFindingSeverity",
            reason: "must be critical, high, medium, low, or info".to_owned(),
        });
    }
    if let Some(resource) = finding.resource.as_deref() {
        validate_text("nativeReadinessFindingResource", resource)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report() -> Vec<u8> {
        br#"{
            "provider":"aws",
            "scope":"123456789012",
            "transport":"allowlisted aws CLI API calls",
            "auth_status":"configured",
            "score":82,
            "checks":[{"check":"compute-inventory","status":"pass","summary":"inspected 3 EC2 instances"}],
            "findings":[{"id":"aws.ec2.imdsv2.i-123","severity":"high","category":"security-baseline","title":"EC2 instance does not require IMDSv2","detail":"Instance metadata tokens are not set to required.","recommendation":"mutating recommendation must not persist","resource":"i-123"}],
            "notes":["scanner note must not persist"],
            "collected_at":"2026-09-15T22:00:00Z"
        }"#
        .to_vec()
    }

    #[test]
    fn converts_native_scan_without_persisting_recommendation_or_notes() -> Result<(), AuditError> {
        let bundle = native_readiness_to_evidence(
            "tenant-a",
            "organization/acme",
            1_700_000_000,
            3_600,
            "canonical-mcp-server.rs@1",
            &report(),
        )?;
        assert_eq!(bundle.observations.len(), 3);
        let encoded = serde_json::to_string(&bundle)?;
        assert!(!encoded.contains("mutating recommendation"));
        assert!(!encoded.contains("scanner note"));
        assert!(encoded.contains("readiness.finding"));
        Ok(())
    }

    #[test]
    fn rejects_unrecognized_transport_even_for_known_provider() {
        let fixture = report();
        let text = String::from_utf8_lossy(&fixture);
        let input = text
            .replace("allowlisted aws CLI API calls", "arbitrary shell")
            .into_bytes();
        assert!(
            native_readiness_to_evidence(
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
