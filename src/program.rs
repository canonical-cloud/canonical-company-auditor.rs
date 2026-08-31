//! Versioned framework metadata and Canonical-authored deterministic assessment rules.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::AuditError;
use crate::evidence::digest;
use crate::model::{FrameworkMapping, Severity};

/// Program schema accepted by this release.
pub const PROGRAM_SCHEMA: &str = "canonical.assessment-program/v1";

/// A versioned, reviewable set of whole-company assessment tests.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssessmentProgram {
    /// Versioned program boundary.
    pub schema_version: String,
    /// Stable program identifier.
    pub program_id: String,
    /// Immutable semantic version.
    pub version: String,
    /// Framework metadata, provenance, and redistribution classification.
    pub frameworks: Vec<FrameworkDescriptor>,
    /// Canonical-authored tests.
    pub rules: Vec<AssessmentRule>,
}

/// Metadata for a standards or regulatory overlay.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrameworkDescriptor {
    /// Stable framework identifier used by manifests and mappings.
    pub id: String,
    /// Public title.
    pub title: String,
    /// Version pinned by the program.
    pub version: String,
    /// Issuing authority.
    pub authority: String,
    /// Authoritative source URL.
    pub source_url: String,
    /// Redistribution policy for embedded content.
    pub redistribution: String,
    /// Maintenance note, including known pending revisions.
    pub status_note: String,
}

/// A single framework-neutral fact test with optional standards mappings.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssessmentRule {
    /// Stable Canonical-authored rule identifier.
    pub id: String,
    /// Concise test title.
    pub title: String,
    /// Governance, people, process, technology, data, vendor, privacy, or resilience workstream.
    pub category: String,
    /// Materiality when the test fails.
    pub severity: Severity,
    /// Framework-neutral evidence type consumed by the test.
    pub evidence_type: String,
    /// Deterministic fact comparison.
    pub condition: RuleCondition,
    /// Reference identifiers only; no protected standard text.
    pub framework_mappings: Vec<FrameworkMapping>,
    /// Canonical-authored remediation guidance.
    pub remediation: String,
}

/// A bounded comparison applied to one normalized fact.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuleCondition {
    /// Fact key within an observation.
    pub fact: String,
    /// Supported deterministic comparison.
    pub operator: ConditionOperator,
    /// Expected scalar value.
    pub expected: Value,
}

/// Operators intentionally kept small enough to review and reproduce in other runtimes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConditionOperator {
    /// Exact JSON scalar equality.
    Equals,
    /// Numeric actual value must be at least the expected value.
    NumberAtLeast,
    /// Numeric actual value must be at most the expected value.
    NumberAtMost,
    /// String or array actual value must be non-empty; expected must be `true`.
    NonEmpty,
}

impl AssessmentProgram {
    /// Parses and validates a program from JSON.
    ///
    /// # Errors
    ///
    /// Returns an [`AuditError`] when JSON parsing or program validation fails.
    pub fn from_json(bytes: &[u8]) -> Result<Self, AuditError> {
        let program: Self = serde_json::from_slice(bytes)?;
        program.validate()?;
        Ok(program)
    }

    /// Validates identifiers, framework provenance, rule uniqueness, and mapping references.
    ///
    /// # Errors
    ///
    /// Returns an [`AuditError`] when a version, provenance, identifier, rule, condition, or
    /// mapping invariant is violated.
    pub fn validate(&self) -> Result<(), AuditError> {
        if self.schema_version != PROGRAM_SCHEMA {
            return Err(AuditError::UnsupportedVersion(self.schema_version.clone()));
        }
        validate_identifier("programId", &self.program_id)?;
        validate_identifier("version", &self.version)?;
        if self.frameworks.is_empty() || self.rules.is_empty() {
            return Err(AuditError::Invalid {
                field: "program",
                reason: "requires at least one framework and one rule".to_owned(),
            });
        }

        let mut framework_ids = BTreeSet::new();
        for framework in &self.frameworks {
            validate_identifier("framework id", &framework.id)?;
            if !framework_ids.insert(framework.id.as_str()) {
                return Err(AuditError::Invalid {
                    field: "frameworks",
                    reason: "contains duplicate identifiers".to_owned(),
                });
            }
            if !framework.source_url.starts_with("https://")
                || framework.redistribution.trim().is_empty()
                || framework.status_note.trim().is_empty()
            {
                return Err(AuditError::Invalid {
                    field: "frameworks",
                    reason: "every framework needs HTTPS provenance and redistribution metadata"
                        .to_owned(),
                });
            }
        }

        let mut rule_ids = BTreeSet::new();
        for rule in &self.rules {
            validate_identifier("rule id", &rule.id)?;
            validate_identifier("evidence type", &rule.evidence_type)?;
            validate_identifier("fact", &rule.condition.fact)?;
            if !rule_ids.insert(rule.id.as_str()) {
                return Err(AuditError::Invalid {
                    field: "rules",
                    reason: "contains duplicate identifiers".to_owned(),
                });
            }
            if rule.remediation.trim().is_empty() {
                return Err(AuditError::Invalid {
                    field: "remediation",
                    reason: "must not be empty".to_owned(),
                });
            }
            for mapping in &rule.framework_mappings {
                if !framework_ids.contains(mapping.framework_id.as_str()) {
                    return Err(AuditError::Invalid {
                        field: "frameworkMappings",
                        reason: "references an unknown framework".to_owned(),
                    });
                }
                validate_reference(&mapping.reference)?;
            }
            validate_condition(&rule.condition)?;
        }
        Ok(())
    }

    /// Returns the canonical digest of the exact program.
    ///
    /// # Errors
    ///
    /// Returns an [`AuditError`] when canonical serialization fails.
    pub fn sha256(&self) -> Result<String, AuditError> {
        digest(self)
    }

    /// Finds one framework descriptor by stable identifier.
    #[must_use]
    pub fn framework(&self, id: &str) -> Option<&FrameworkDescriptor> {
        self.frameworks.iter().find(|framework| framework.id == id)
    }
}

/// Loads the reviewed built-in top-to-bottom baseline.
///
/// # Errors
///
/// Returns an [`AuditError`] when the embedded program does not parse or validate.
pub fn built_in_program() -> Result<AssessmentProgram, AuditError> {
    AssessmentProgram::from_json(include_bytes!("../programs/baseline-v1.json"))
}

fn validate_condition(condition: &RuleCondition) -> Result<(), AuditError> {
    let valid = match condition.operator {
        ConditionOperator::Equals => {
            condition.expected.is_boolean()
                || condition.expected.is_number()
                || condition.expected.is_string()
        }
        ConditionOperator::NumberAtLeast | ConditionOperator::NumberAtMost => {
            condition.expected.as_f64().is_some()
        }
        ConditionOperator::NonEmpty => condition.expected == Value::Bool(true),
    };
    if !valid {
        return Err(AuditError::Invalid {
            field: "condition",
            reason: "operator and expected scalar type do not match".to_owned(),
        });
    }
    Ok(())
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), AuditError> {
    if value.is_empty()
        || value.len() > 160
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'@')
        })
    {
        return Err(AuditError::Invalid {
            field,
            reason: "must contain 1..=160 safe identifier bytes".to_owned(),
        });
    }
    Ok(())
}

fn validate_reference(value: &str) -> Result<(), AuditError> {
    if value.is_empty()
        || value.len() > 120
        || value.chars().any(char::is_control)
        || value.trim() != value
    {
        return Err(AuditError::Invalid {
            field: "reference",
            reason: "must be trimmed public reference text no longer than 120 bytes".to_owned(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn built_in_program_is_valid_and_provenanced() -> Result<(), AuditError> {
        let program = built_in_program()?;
        assert!(program.rules.len() >= 15);
        assert!(program.frameworks.len() >= 8);
        assert!(program.sha256()?.starts_with("sha256:"));
        Ok(())
    }
}
