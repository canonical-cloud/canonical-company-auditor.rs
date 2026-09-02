//! Canonicalization, content addressing, tenant/scope checks, and evidence sealing.

use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::AuditError;
use crate::model::{CompanyManifest, EvidenceBundle, EvidenceObservation, scope_contains};

const MAX_FACT_BYTES: usize = 64 * 1024;

/// One input observation with computed integrity metadata.
#[derive(Clone, Debug)]
pub struct SealedObservation {
    /// Deterministic identifier bound to provenance, timestamps, subject, and fact digest.
    pub observation_id: String,
    /// Canonical SHA-256 of normalized facts.
    pub facts_sha256: String,
    /// Validated source observation.
    pub input: EvidenceObservation,
}

/// A validated evidence bundle ready for deterministic evaluation.
#[derive(Clone, Debug)]
pub struct SealedEvidence {
    /// Canonical SHA-256 of the complete source bundle.
    pub evidence_sha256: String,
    /// Deterministically sorted observations.
    pub observations: Vec<SealedObservation>,
}

/// Validates and seals evidence under the manifest's exact tenant and hierarchical scope.
///
/// # Errors
///
/// Returns an [`AuditError`] for invalid inputs, cross-boundary evidence, oversized facts, or
/// canonical serialization failure.
pub fn seal_evidence(
    manifest: &CompanyManifest,
    bundle: &EvidenceBundle,
) -> Result<SealedEvidence, AuditError> {
    manifest.validate()?;
    bundle.validate()?;
    if manifest.tenant_id != bundle.tenant_id
        || manifest.scope_id != bundle.scope_id
        || !scope_contains(&manifest.scope_id, &bundle.scope_id)
    {
        return Err(AuditError::ScopeDenied);
    }

    let mut observations = Vec::with_capacity(bundle.observations.len());
    for input in &bundle.observations {
        if !scope_contains(&manifest.scope_id, &input.subject) {
            return Err(AuditError::ScopeDenied);
        }
        let fact_bytes = canonical_json_bytes(&input.facts)?;
        if fact_bytes.len() > MAX_FACT_BYTES {
            return Err(AuditError::Invalid {
                field: "facts",
                reason: format!("canonical facts exceed {MAX_FACT_BYTES} bytes"),
            });
        }
        let facts_sha256 = sha256(&fact_bytes);
        let observation_id = digest(&(
            "canonical.evidence-observation/v1",
            &manifest.tenant_id,
            &input.external_id,
            &input.evidence_type,
            &input.subject,
            &input.source,
            input.collected_at,
            input.valid_until,
            &facts_sha256,
            &input.attestation,
        ))?;
        observations.push(SealedObservation {
            observation_id,
            facts_sha256,
            input: input.clone(),
        });
    }
    observations.sort_by(|left, right| left.observation_id.cmp(&right.observation_id));

    Ok(SealedEvidence {
        evidence_sha256: digest(bundle)?,
        observations,
    })
}

/// Returns canonical `sha256:<hex>` for a serializable value.
///
/// # Errors
///
/// Returns an [`AuditError`] when the value cannot be serialized as canonical JSON.
pub fn digest<T: Serialize>(value: &T) -> Result<String, AuditError> {
    Ok(sha256(&canonical_json_bytes(value)?))
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn canonical_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, AuditError> {
    let value = serde_json::to_value(value)?;
    Ok(serde_json::to_vec(&canonicalize(value))?)
}

fn canonicalize(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(canonicalize).collect()),
        Value::Object(values) => {
            let mut entries = values.into_iter().collect::<Vec<_>>();
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            Value::Object(
                entries
                    .into_iter()
                    .map(|(key, nested)| (key, canonicalize(nested)))
                    .collect::<Map<_, _>>(),
            )
        }
        scalar => scalar,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::json;

    use super::*;

    #[test]
    fn nested_object_order_does_not_change_digest() -> Result<(), AuditError> {
        let first = json!({"outer": {"b": 2, "a": 1}});
        let second = json!({"outer": {"a": 1, "b": 2}});
        assert_eq!(digest(&first)?, digest(&second)?);
        Ok(())
    }

    #[test]
    fn different_facts_change_digest() -> Result<(), AuditError> {
        let first = BTreeMap::from([("enabled".to_owned(), json!(true))]);
        let second = BTreeMap::from([("enabled".to_owned(), json!(false))]);
        assert_ne!(digest(&first)?, digest(&second)?);
        Ok(())
    }
}
