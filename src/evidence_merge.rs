//! Deterministic composition of evidence collected by independent read-only engines.
//!
//! Native cloud adapters, external scanners, runtime probes, and manual workflows can all
//! produce separate `EvidenceBundle` values for the same explicit tenant/scope. This module
//! combines those bundles without weakening tenant isolation, silently accepting conflicting
//! identities, or introducing ordering-dependent report digests.

use std::collections::BTreeMap;

use crate::AuditError;
use crate::evidence::digest;
use crate::model::{EVIDENCE_SCHEMA, EvidenceBundle, EvidenceObservation};

/// Merge multiple validated evidence bundles for one exact tenant/scope.
///
/// Output is deterministic: observations are ordered by `external_id`. Repeated identical
/// observations collapse to one record. If two bundles reuse an `external_id` for different
/// content, the merge fails closed rather than choosing one source.
///
/// # Errors
///
/// Returns [`AuditError`] if any bundle is invalid, bundle tenant/scope values differ, a
/// duplicate external identifier carries conflicting content, or the merged bundle exceeds
/// normal `EvidenceBundle` limits.
pub fn merge_evidence_bundles(
    bundles: &[EvidenceBundle],
) -> Result<EvidenceBundle, AuditError> {
    let first = bundles.first().ok_or_else(|| AuditError::Invalid {
        field: "evidenceBundles",
        reason: "at least one evidence bundle is required".to_owned(),
    })?;
    first.validate()?;

    let tenant_id = first.tenant_id.clone();
    let scope_id = first.scope_id.clone();
    let mut observations: BTreeMap<String, (String, EvidenceObservation)> = BTreeMap::new();

    for bundle in bundles {
        bundle.validate()?;
        if bundle.schema_version != EVIDENCE_SCHEMA
            || bundle.tenant_id != tenant_id
            || bundle.scope_id != scope_id
        {
            return Err(AuditError::ScopeDenied);
        }

        for observation in &bundle.observations {
            let observation_digest = digest(observation)?;
            match observations.get(&observation.external_id) {
                Some((existing_digest, _)) if existing_digest != &observation_digest => {
                    return Err(AuditError::Integrity);
                }
                Some(_) => {}
                None => {
                    observations.insert(
                        observation.external_id.clone(),
                        (observation_digest, observation.clone()),
                    );
                }
            }
        }
    }

    let merged = EvidenceBundle {
        schema_version: EVIDENCE_SCHEMA.to_owned(),
        tenant_id,
        scope_id,
        observations: observations
            .into_values()
            .map(|(_, observation)| observation)
            .collect(),
    };
    merged.validate()?;
    Ok(merged)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::json;

    use super::*;
    use crate::model::EvidenceSource;

    fn observation(external_id: &str, value: bool) -> EvidenceObservation {
        EvidenceObservation {
            external_id: external_id.to_owned(),
            evidence_type: "scanner.finding".to_owned(),
            subject: "organization/acme".to_owned(),
            source: EvidenceSource::Connector {
                connector: "external.prowler".to_owned(),
                adapter_version: "1.0.0".to_owned(),
            },
            collected_at: 1_700_000_000,
            valid_until: 1_700_003_600,
            facts: BTreeMap::from([("observed".to_owned(), json!(value))]),
            attestation: None,
        }
    }

    fn bundle(observations: Vec<EvidenceObservation>) -> EvidenceBundle {
        EvidenceBundle {
            schema_version: EVIDENCE_SCHEMA.to_owned(),
            tenant_id: "tenant-a".to_owned(),
            scope_id: "organization/acme".to_owned(),
            observations,
        }
    }

    #[test]
    fn merge_is_order_independent_and_deduplicates_identical_observations(
    ) -> Result<(), AuditError> {
        let one = bundle(vec![observation("a", true), observation("b", false)]);
        let two = bundle(vec![observation("b", false), observation("c", true)]);
        let forward = merge_evidence_bundles(&[one.clone(), two.clone()])?;
        let reverse = merge_evidence_bundles(&[two, one])?;
        assert_eq!(forward, reverse);
        assert_eq!(forward.observations.len(), 3);
        assert_eq!(forward.observations[0].external_id, "a");
        assert_eq!(forward.observations[2].external_id, "c");
        Ok(())
    }

    #[test]
    fn duplicate_external_id_with_different_content_fails_closed() {
        let one = bundle(vec![observation("same", true)]);
        let two = bundle(vec![observation("same", false)]);
        assert!(matches!(
            merge_evidence_bundles(&[one, two]),
            Err(AuditError::Integrity)
        ));
    }

    #[test]
    fn cross_tenant_or_scope_merge_is_denied() {
        let one = bundle(vec![observation("a", true)]);
        let mut two = bundle(vec![observation("b", true)]);
        two.tenant_id = "tenant-b".to_owned();
        assert!(matches!(
            merge_evidence_bundles(&[one, two]),
            Err(AuditError::ScopeDenied)
        ));
    }
}
