//! Deterministic aggregation for normalized external scanner observations.
//!
//! These helpers intentionally summarize scanner *signals*, not compliance conclusions.
//! Agreement between scanners is useful corroboration, but it is never converted into a
//! Canonical control pass/fail without a Canonical-authored deterministic rule.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use serde_json::Value;

use crate::AuditError;
use crate::evidence::digest;
use crate::model::{EvidenceBundle, EvidenceObservation};

/// Stable, time-independent identity for a normalized scanner finding.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScannerFindingFingerprint {
    /// Canonical SHA-256 over scanner identity and normalized finding identity.
    pub fingerprint: String,
    /// External scanner name such as `prowler` or `trivy`.
    pub tool: String,
    /// Optional cloud/provider label.
    pub provider: Option<String>,
    /// Scanner-native finding identifier.
    pub scanner_finding_id: String,
    /// Optional resource identifier reported by the scanner.
    pub resource: Option<String>,
}

/// Framework-neutral summary of multiple scanner signals attached to one resource.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScannerResourceSignals {
    /// Provider label when one was present on the source observations.
    pub provider: Option<String>,
    /// Exact scanner-reported resource identifier.
    pub resource: String,
    /// Distinct scanners that emitted findings for the resource.
    pub tools: Vec<String>,
    /// Highest scanner-reported severity, using Canonical's ordering only for sorting.
    pub highest_severity: String,
    /// Number of normalized scanner finding observations for this resource.
    pub finding_count: usize,
    /// Stable fingerprints with repeated equivalent observations collapsed.
    pub unique_fingerprints: Vec<String>,
    /// Source observation identifiers retained for provenance lookup.
    pub observation_ids: Vec<String>,
}

/// Compute a time-independent fingerprint for one normalized `scanner.finding` observation.
///
/// The source observation's collection timestamp is intentionally excluded so the same
/// scanner finding can be recognized across repeated scans. This function does not claim
/// that findings from different tools are equivalent.
///
/// # Errors
///
/// Returns [`AuditError`] if a `scanner.finding` observation is malformed.
pub fn scanner_finding_fingerprint(
    observation: &EvidenceObservation,
) -> Result<Option<ScannerFindingFingerprint>, AuditError> {
    if observation.evidence_type != "scanner.finding" {
        return Ok(None);
    }
    let tool = required_fact(observation, "tool")?;
    let scanner_finding_id = required_fact(observation, "scannerFindingId")?;
    let provider = optional_fact(observation, "provider")?;
    let resource = optional_fact(observation, "resource")?;
    let title = required_fact(observation, "title")?;
    let fingerprint = digest(&(
        "canonical.external-scanner-fingerprint/v1",
        tool,
        provider.as_deref(),
        scanner_finding_id,
        resource.as_deref(),
        title,
    ))?;
    Ok(Some(ScannerFindingFingerprint {
        fingerprint,
        tool: tool.to_owned(),
        provider,
        scanner_finding_id: scanner_finding_id.to_owned(),
        resource,
    }))
}

/// Summarize explicit resource-level scanner signals without treating tool agreement as a
/// compliance verdict.
///
/// Findings that do not name a resource remain valid evidence but are intentionally omitted
/// from this resource-specific aggregation. Equivalent repeated findings from the same tool
/// are deduplicated by [`scanner_finding_fingerprint`].
///
/// # Errors
///
/// Returns [`AuditError`] when the evidence bundle or a scanner finding is malformed.
pub fn summarize_scanner_resources(
    bundle: &EvidenceBundle,
) -> Result<Vec<ScannerResourceSignals>, AuditError> {
    bundle.validate()?;
    let mut groups: BTreeMap<(Option<String>, String), ResourceAccumulator> = BTreeMap::new();

    for observation in &bundle.observations {
        let Some(fingerprint) = scanner_finding_fingerprint(observation)? else {
            continue;
        };
        let Some(resource) = fingerprint.resource.clone() else {
            continue;
        };
        let severity = required_fact(observation, "severity")?.to_owned();
        let key = (fingerprint.provider.clone(), resource.clone());
        let group = groups.entry(key).or_default();
        group.tools.insert(fingerprint.tool);
        group.finding_count += 1;
        group.highest_severity = choose_higher(&group.highest_severity, &severity).to_owned();
        group.unique_fingerprints.insert(fingerprint.fingerprint);
        group
            .observation_ids
            .insert(observation.external_id.clone());
    }

    Ok(groups
        .into_iter()
        .map(|((provider, resource), group)| ScannerResourceSignals {
            provider,
            resource,
            tools: group.tools.into_iter().collect(),
            highest_severity: group.highest_severity,
            finding_count: group.finding_count,
            unique_fingerprints: group.unique_fingerprints.into_iter().collect(),
            observation_ids: group.observation_ids.into_iter().collect(),
        })
        .collect())
}

#[derive(Default)]
struct ResourceAccumulator {
    tools: BTreeSet<String>,
    highest_severity: String,
    finding_count: usize,
    unique_fingerprints: BTreeSet<String>,
    observation_ids: BTreeSet<String>,
}

fn required_fact<'a>(
    observation: &'a EvidenceObservation,
    key: &'static str,
) -> Result<&'a str, AuditError> {
    observation
        .facts
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AuditError::Invalid {
            field: "scannerFinding",
            reason: format!("scanner.finding is missing string fact {key}"),
        })
}

fn optional_fact(
    observation: &EvidenceObservation,
    key: &'static str,
) -> Result<Option<String>, AuditError> {
    match observation.facts.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if !value.is_empty() => Ok(Some(value.clone())),
        Some(_) => Err(AuditError::Invalid {
            field: "scannerFinding",
            reason: format!("scanner.finding fact {key} must be a non-empty string"),
        }),
    }
}

fn choose_higher<'a>(left: &'a str, right: &'a str) -> &'a str {
    if severity_rank(right) > severity_rank(left) {
        right
    } else {
        left
    }
}

fn severity_rank(value: &str) -> u8 {
    match value {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        "info" => 1,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::external_evidence::external_scan_to_evidence;

    fn report() -> Vec<u8> {
        br#"{
            "tool":"prowler",
            "provider":"aws",
            "status":"completed",
            "read_only":true,
            "exit_code":0,
            "counts":{"failed":2,"total_records":2},
            "findings":[
                {"id":"iam.1","severity":"medium","title":"Public principal","detail":"first","resource":"arn:aws:iam::123:role/example"},
                {"id":"iam.2","severity":"high","title":"MFA missing","detail":"second","resource":"arn:aws:iam::123:role/example"}
            ]
        }"#
        .to_vec()
    }

    #[test]
    fn summarizes_resource_signals_without_creating_control_outcomes() -> Result<(), AuditError> {
        let bundle = external_scan_to_evidence(
            "tenant-a",
            "organization/acme",
            1_700_000_000,
            3_600,
            "mcp@1",
            &report(),
        )?;
        let summary = summarize_scanner_resources(&bundle)?;
        assert_eq!(summary.len(), 1);
        assert_eq!(summary[0].finding_count, 2);
        assert_eq!(summary[0].highest_severity, "high");
        assert_eq!(summary[0].tools, vec!["prowler"]);
        assert_eq!(summary[0].unique_fingerprints.len(), 2);
        Ok(())
    }

    #[test]
    fn fingerprint_is_stable_across_collection_times() -> Result<(), AuditError> {
        let first_bundle = external_scan_to_evidence(
            "tenant-a",
            "organization/acme",
            1_700_000_000,
            300,
            "mcp@1",
            &report(),
        )?;
        let second_bundle = external_scan_to_evidence(
            "tenant-a",
            "organization/acme",
            1_700_000_600,
            300,
            "mcp@1",
            &report(),
        )?;
        let first = scanner_finding_fingerprint(&first_bundle.observations[1])?
            .ok_or(AuditError::Integrity)?;
        let second = scanner_finding_fingerprint(&second_bundle.observations[1])?
            .ok_or(AuditError::Integrity)?;
        assert_eq!(first.fingerprint, second.fingerprint);
        assert_ne!(
            first_bundle.observations[1].external_id,
            second_bundle.observations[1].external_id
        );
        Ok(())
    }
}
