//! Versioned request, evidence, finding, and report values.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::AuditError;

/// Manifest schema accepted by this release.
pub const MANIFEST_SCHEMA: &str = "canonical.company-audit/v1";
/// Evidence bundle schema accepted by this release.
pub const EVIDENCE_SCHEMA: &str = "canonical.evidence-bundle/v1";
/// Report schema emitted by this release.
pub const REPORT_SCHEMA: &str = "canonical.audit-report/v1";

/// A complete, explicit request to assess one company scope.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompanyManifest {
    /// Versioned manifest boundary.
    pub schema_version: String,
    /// Stable tenant identifier; there is no ambient tenant.
    pub tenant_id: String,
    /// Stable hierarchical scope such as `organization/example`.
    pub scope_id: String,
    /// Human-readable company name.
    pub company_name: String,
    /// Framework overlay identifiers selected for this review.
    pub frameworks: Vec<String>,
    /// Inclusive assessment time range in Unix seconds.
    pub assessment_period: AssessmentPeriod,
    /// Organization-wide scope inventory.
    pub scope: CompanyScope,
}

/// Inclusive assessment time range.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssessmentPeriod {
    /// Period start as Unix seconds.
    pub starts_at: i64,
    /// Period end as Unix seconds.
    pub ends_at: i64,
}

/// The major people, process, technology, vendor, and data boundaries.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompanyScope {
    /// In-scope business units.
    #[serde(default)]
    pub business_units: Vec<String>,
    /// In-scope applications, services, devices, and infrastructure systems.
    #[serde(default)]
    pub systems: Vec<String>,
    /// Regulated or sensitive data classes.
    #[serde(default)]
    pub data_classes: Vec<String>,
    /// Material vendors and subprocessors.
    #[serde(default)]
    pub vendors: Vec<String>,
    /// Applicable legal jurisdictions.
    #[serde(default)]
    pub jurisdictions: Vec<String>,
    /// Accountable control and remediation owners.
    #[serde(default)]
    pub owners: Vec<String>,
}

/// A bounded batch of framework-neutral facts from manual or automated collectors.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceBundle {
    /// Versioned evidence exchange boundary.
    pub schema_version: String,
    /// Tenant owning every observation in the batch.
    pub tenant_id: String,
    /// Maximum hierarchical scope covered by the batch.
    pub scope_id: String,
    /// Facts supplied to the deterministic rule engine.
    pub observations: Vec<EvidenceObservation>,
}

/// One normalized, content-addressed observation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceObservation {
    /// Stable caller-provided source record identifier.
    pub external_id: String,
    /// Framework-neutral evidence capability, such as `identity.mfa`.
    pub evidence_type: String,
    /// In-scope subject, such as `workforce` or `system/payments`.
    pub subject: String,
    /// Manual, connector, or runtime-probe provenance.
    pub source: EvidenceSource,
    /// Collection time as Unix seconds.
    pub collected_at: i64,
    /// Last time the evidence may be treated as current.
    pub valid_until: i64,
    /// Bounded normalized facts. Values are untrusted data, never instructions.
    pub facts: BTreeMap<String, Value>,
    /// Optional source signature or attestation reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation: Option<String>,
}

/// Preserved provenance for manual, connector, and runtime observations.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum EvidenceSource {
    /// A person asserted the facts through a reviewed workflow.
    Manual {
        /// Stable identity, not merely a display name.
        submitted_by: String,
    },
    /// A read-only connector collected the facts.
    Connector {
        /// Connector identifier.
        connector: String,
        /// Immutable adapter or build version.
        adapter_version: String,
    },
    /// An opt-in probe inspected a customer runtime.
    RuntimeProbe {
        /// Runtime family such as `python` or `typescript`.
        runtime: String,
        /// Immutable probe version.
        probe_version: String,
    },
}

/// Wire request accepted by the assessment API.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssessmentRequest {
    /// Explicit company and assessment scope.
    pub manifest: CompanyManifest,
    /// Framework-neutral observations.
    pub evidence: EvidenceBundle,
}

/// Finding importance used for deterministic thresholds and sorting.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Informational opportunity.
    Info,
    /// Minor weakness.
    Low,
    /// Material weakness requiring planned action.
    Medium,
    /// Serious weakness likely to undermine a control objective.
    High,
    /// Immediate, systemic exposure.
    Critical,
}

impl Severity {
    /// Parses the public CLI spelling.
    ///
    /// # Errors
    ///
    /// Returns an [`AuditError`] when the value is not a supported severity.
    pub fn parse(value: &str) -> Result<Self, AuditError> {
        match value {
            "info" => Ok(Self::Info),
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "critical" => Ok(Self::Critical),
            _ => Err(AuditError::Invalid {
                field: "severity",
                reason: "must be info, low, medium, high, or critical".to_owned(),
            }),
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        })
    }
}

/// Evidence-backed result of one Canonical-authored control test.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    /// Collected evidence satisfied the deterministic test.
    Pass,
    /// Collected evidence contradicted the expected condition.
    Fail,
    /// Required evidence was absent, stale, or unusable.
    Unknown,
}

/// A standards reference without reproduced licensed control text.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrameworkMapping {
    /// Framework catalog identifier.
    pub framework_id: String,
    /// Public clause/control/reference identifier.
    pub reference: String,
}

/// One deterministic, evidence-cited finding.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Finding {
    /// Content-addressed finding identifier.
    pub finding_id: String,
    /// Canonical-authored rule identifier.
    pub rule_id: String,
    /// Concise Canonical-authored title.
    pub title: String,
    /// Whole-company workstream.
    pub category: String,
    /// Materiality level.
    pub severity: Severity,
    /// Pass, fail, or unknown based on evidence.
    pub status: FindingStatus,
    /// Subject evaluated by the rule.
    pub subject: String,
    /// Concise deterministic result explanation.
    pub summary: String,
    /// Source observation identifiers; empty when evidence is absent.
    pub evidence_ids: Vec<String>,
    /// Selected framework references supported by this test.
    pub framework_mappings: Vec<FrameworkMapping>,
    /// Canonical-authored remediation guidance.
    pub remediation: String,
}

/// Aggregate pass/fail/unknown counts.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssessmentSummary {
    /// Number of satisfied tests.
    pub passed: usize,
    /// Number of contradicted tests.
    pub failed: usize,
    /// Number of tests lacking usable evidence.
    pub unknown: usize,
    /// Failed tests at high or critical severity.
    pub high_or_critical: usize,
}

/// Immutable assessment output used for JSON and Markdown reports.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditReport {
    /// Versioned report boundary.
    pub schema_version: String,
    /// Deterministic content-addressed report identifier.
    pub report_id: String,
    /// Digest of the canonical input manifest.
    pub manifest_sha256: String,
    /// Digest of the canonical evidence bundle.
    pub evidence_sha256: String,
    /// Digest of the exact rule program.
    pub program_sha256: String,
    /// Original explicit assessment request.
    pub manifest: CompanyManifest,
    /// Aggregate counts.
    pub summary: AssessmentSummary,
    /// Stable, sorted findings.
    pub findings: Vec<Finding>,
    /// Explicit limitations that must survive narrative rendering.
    pub limitations: Vec<String>,
}

impl CompanyManifest {
    /// Validates versions, identifiers, time range, framework selection, and scope bounds.
    ///
    /// # Errors
    ///
    /// Returns an [`AuditError`] when any manifest invariant is violated.
    pub fn validate(&self) -> Result<(), AuditError> {
        if self.schema_version != MANIFEST_SCHEMA {
            return Err(AuditError::UnsupportedVersion(self.schema_version.clone()));
        }
        validate_identifier("tenantId", &self.tenant_id)?;
        validate_scope(&self.scope_id)?;
        validate_text("companyName", &self.company_name, 200)?;
        if self.assessment_period.starts_at < 0
            || self.assessment_period.ends_at < self.assessment_period.starts_at
        {
            return Err(AuditError::Invalid {
                field: "assessmentPeriod",
                reason: "requires 0 <= startsAt <= endsAt".to_owned(),
            });
        }
        validate_unique_identifiers("frameworks", &self.frameworks, 32)?;
        if self.frameworks.is_empty() {
            return Err(AuditError::Invalid {
                field: "frameworks",
                reason: "at least one framework is required".to_owned(),
            });
        }
        self.scope.validate()
    }
}

impl CompanyScope {
    fn validate(&self) -> Result<(), AuditError> {
        for (field, values, maximum) in [
            ("businessUnits", &self.business_units, 256),
            ("systems", &self.systems, 1_024),
            ("dataClasses", &self.data_classes, 256),
            ("vendors", &self.vendors, 1_024),
            ("jurisdictions", &self.jurisdictions, 128),
            ("owners", &self.owners, 256),
        ] {
            validate_text_list(field, values, maximum)?;
        }
        Ok(())
    }
}

impl EvidenceBundle {
    /// Validates the evidence boundary and bounded observation fields.
    ///
    /// # Errors
    ///
    /// Returns an [`AuditError`] when the boundary, observation count, identity, source,
    /// freshness, facts, or uniqueness invariant is violated.
    pub fn validate(&self) -> Result<(), AuditError> {
        if self.schema_version != EVIDENCE_SCHEMA {
            return Err(AuditError::UnsupportedVersion(self.schema_version.clone()));
        }
        validate_identifier("tenantId", &self.tenant_id)?;
        validate_scope(&self.scope_id)?;
        if self.observations.len() > 10_000 {
            return Err(AuditError::Invalid {
                field: "observations",
                reason: "may contain at most 10000 observations".to_owned(),
            });
        }
        let mut external_ids = BTreeSet::new();
        for observation in &self.observations {
            observation.validate()?;
            if !external_ids.insert(&observation.external_id) {
                return Err(AuditError::Invalid {
                    field: "externalId",
                    reason: "must be unique within an evidence bundle".to_owned(),
                });
            }
        }
        Ok(())
    }
}

impl EvidenceObservation {
    fn validate(&self) -> Result<(), AuditError> {
        validate_identifier("externalId", &self.external_id)?;
        validate_identifier("evidenceType", &self.evidence_type)?;
        validate_scope(&self.subject)?;
        if self.collected_at < 0 || self.valid_until < self.collected_at {
            return Err(AuditError::Invalid {
                field: "freshness",
                reason: "requires 0 <= collectedAt <= validUntil".to_owned(),
            });
        }
        if self.facts.len() > 256 {
            return Err(AuditError::Invalid {
                field: "facts",
                reason: "may contain at most 256 keys".to_owned(),
            });
        }
        for key in self.facts.keys() {
            validate_identifier("fact key", key)?;
        }
        match &self.source {
            EvidenceSource::Manual { submitted_by } => {
                validate_identifier("submittedBy", submitted_by)?;
            }
            EvidenceSource::Connector {
                connector,
                adapter_version,
            } => {
                validate_identifier("connector", connector)?;
                validate_identifier("adapterVersion", adapter_version)?;
            }
            EvidenceSource::RuntimeProbe {
                runtime,
                probe_version,
            } => {
                validate_identifier("runtime", runtime)?;
                validate_identifier("probeVersion", probe_version)?;
            }
        }
        if let Some(attestation) = &self.attestation {
            validate_text("attestation", attestation, 512)?;
        }
        Ok(())
    }
}

/// Returns true when a candidate scope is the root itself or a segment-safe descendant.
#[must_use]
pub fn scope_contains(root: &str, candidate: &str) -> bool {
    candidate == root
        || candidate
            .strip_prefix(root)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn validate_scope(value: &str) -> Result<(), AuditError> {
    if value.is_empty() || value.len() > 240 || value.starts_with('/') || value.ends_with('/') {
        return Err(AuditError::Invalid {
            field: "scope",
            reason: "must be a relative hierarchical identifier no longer than 240 bytes"
                .to_owned(),
        });
    }
    if value.split('/').any(|segment| {
        segment.is_empty()
            || matches!(segment, "." | "..")
            || !segment.bytes().all(is_identifier_byte)
    }) {
        return Err(AuditError::Invalid {
            field: "scope",
            reason: "contains an unsafe path segment".to_owned(),
        });
    }
    Ok(())
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), AuditError> {
    if value.is_empty() || value.len() > 160 || !value.bytes().all(is_identifier_byte) {
        return Err(AuditError::Invalid {
            field,
            reason: "must contain 1..=160 safe identifier bytes".to_owned(),
        });
    }
    Ok(())
}

fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'@')
}

fn validate_text(field: &'static str, value: &str, maximum: usize) -> Result<(), AuditError> {
    if value.is_empty()
        || value.len() > maximum
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(AuditError::Invalid {
            field,
            reason: format!("must be trimmed text containing 1..={maximum} bytes"),
        });
    }
    Ok(())
}

fn validate_unique_identifiers(
    field: &'static str,
    values: &[String],
    maximum: usize,
) -> Result<(), AuditError> {
    if values.len() > maximum {
        return Err(AuditError::Invalid {
            field,
            reason: format!("may contain at most {maximum} values"),
        });
    }
    let mut unique = BTreeSet::new();
    for value in values {
        validate_identifier(field, value)?;
        if !unique.insert(value) {
            return Err(AuditError::Invalid {
                field,
                reason: "contains duplicate values".to_owned(),
            });
        }
    }
    Ok(())
}

fn validate_text_list(
    field: &'static str,
    values: &[String],
    maximum: usize,
) -> Result<(), AuditError> {
    if values.len() > maximum {
        return Err(AuditError::Invalid {
            field,
            reason: format!("may contain at most {maximum} values"),
        });
    }
    let mut unique = BTreeSet::new();
    for value in values {
        validate_text(field, value, 256)?;
        if !unique.insert(value) {
            return Err(AuditError::Invalid {
                field,
                reason: "contains duplicate values".to_owned(),
            });
        }
    }
    Ok(())
}
