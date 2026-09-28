//! Read-only ingestion boundary for repository-specific coding-agent evaluation receipts.
//!
//! Evaluation evidence is normalized into framework-neutral observations. A passing
//! benchmark case is not a compliance, certification, safety, competency, or merge
//! verdict; the auditor only records the exact repository/suite/harness/model facts
//! and preserves all declared non-passing outcomes.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::AuditError;
use crate::evidence::digest;
use crate::model::{EVIDENCE_SCHEMA, EvidenceBundle, EvidenceObservation, EvidenceSource};

const RECEIPT_SCHEMA: &str = "elenkos.agent-eval.receipt.v1";
const RECEIPT_KIND: &str = "evaluation_receipt";
const MAX_RECEIPT_BYTES: usize = 2 * 1024 * 1024;
const MAX_CASE_RESULTS: usize = 1_000;
const MAX_TEXT_BYTES: usize = 512;
const MAX_VALIDITY_SECONDS: i64 = 30 * 24 * 60 * 60;

/// Explicit tenant/scope and repository binding for one imported evaluation receipt.
#[derive(Clone, Copy, Debug)]
pub struct AgentEvalEvidenceContext<'a> {
    /// Tenant that owns the resulting evidence bundle.
    pub tenant_id: &'a str,
    /// Hierarchical company-audit scope that owns the evaluated repository.
    pub scope_id: &'a str,
    /// Exact `owner/repository` expected by the audit request.
    pub expected_repository: &'a str,
    /// Exact repository base SHA expected by the audit request.
    pub expected_base_sha: &'a str,
    /// Evidence collection time in Unix seconds.
    pub collected_at: i64,
    /// Bounded freshness window in seconds.
    pub valid_for_seconds: i64,
    /// Immutable adapter version for this import path.
    pub adapter_version: &'a str,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AgentEvalReceipt {
    kind: String,
    schema_version: String,
    repository: String,
    base_sha: String,
    benchmark_suite: String,
    benchmark_suite_version: String,
    benchmark_suite_sha256: String,
    harness: String,
    harness_version: String,
    harness_sha256: String,
    agent: String,
    model: String,
    provider: String,
    environment_identity: String,
    toolchain_identity: String,
    case_results: Vec<AgentEvalCaseResult>,
    declared_case_count: usize,
    executed_case_count: usize,
    passing_case_count: usize,
    non_passing_case_count: usize,
    result_artifact_sha256: Vec<String>,
    receipt_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AgentEvalCaseResult {
    case_id: String,
    status: AgentEvalCaseStatus,
    candidate_tree_sha: Option<String>,
    verifier_receipt_sha256: Option<String>,
    duration_ms: u64,
    tool_calls: u64,
    retry_count: u64,
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
    observed_cost_usd_micros: Option<u64>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum AgentEvalCaseStatus {
    Passed,
    Failed,
    Skipped,
    Flaky,
    InfraFailed,
    InvalidCase,
}

impl AgentEvalCaseStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::Skipped => "skipped",
            Self::Flaky => "flaky",
            Self::InfraFailed => "infra_failed",
            Self::InvalidCase => "invalid_case",
        }
    }

    fn counts_as_executed(self) -> bool {
        return !matches!(self, Self::Skipped | Self::InvalidCase);
    }
}

#[derive(Serialize)]
struct ReceiptPayload<'a> {
    kind: &'a str,
    schema_version: &'a str,
    repository: &'a str,
    base_sha: &'a str,
    benchmark_suite: &'a str,
    benchmark_suite_version: &'a str,
    benchmark_suite_sha256: &'a str,
    harness: &'a str,
    harness_version: &'a str,
    harness_sha256: &'a str,
    agent: &'a str,
    model: &'a str,
    provider: &'a str,
    environment_identity: &'a str,
    toolchain_identity: &'a str,
    case_results: &'a [AgentEvalCaseResult],
    declared_case_count: usize,
    executed_case_count: usize,
    passing_case_count: usize,
    non_passing_case_count: usize,
    result_artifact_sha256: &'a [String],
}

/// Convert one digest-bound repository-specific coding-agent evaluation receipt into
/// framework-neutral evidence observations.
///
/// The importer requires an exact repository/base binding, verifies the canonical
/// self-digest, rejects denominator/count inconsistencies and duplicate case IDs, and
/// preserves every case result as its own observation. It deliberately does not turn
/// benchmark outcomes into readiness findings; deterministic rules may consume the
/// observations later with explicit framework-neutral semantics.
///
/// # Errors
///
/// Returns [`AuditError`] for malformed/oversized receipts, unsupported versions,
/// repository/base mismatch, stale freshness, invalid digests, duplicate cases,
/// inconsistent coverage counts, or invalid resulting evidence.
pub fn agent_eval_receipt_to_evidence(
    context: AgentEvalEvidenceContext<'_>,
    receipt_json: &[u8],
) -> Result<EvidenceBundle, AuditError> {
    if receipt_json.len() > MAX_RECEIPT_BYTES {
        return Err(invalid(
            "agentEvalReceipt",
            format!("may contain at most {MAX_RECEIPT_BYTES} bytes"),
        ));
    }
    if context.collected_at < 0 || !(1..=MAX_VALIDITY_SECONDS).contains(&context.valid_for_seconds)
    {
        return Err(invalid(
            "agentEvalFreshness",
            format!(
                "requires collectedAt >= 0 and validForSeconds in 1..={MAX_VALIDITY_SECONDS}"
            ),
        ));
    }
    let valid_until = context
        .collected_at
        .checked_add(context.valid_for_seconds)
        .ok_or_else(|| invalid("agentEvalFreshness", "validUntil overflowed"))?;

    let receipt: AgentEvalReceipt = serde_json::from_slice(receipt_json)?;
    validate_receipt(&receipt, &context)?;

    let source = EvidenceSource::Connector {
        connector: "external.agent-eval".to_owned(),
        adapter_version: context.adapter_version.to_owned(),
    };
    let mut observations = Vec::with_capacity(receipt.case_results.len() + 1);
    observations.push(run_observation(
        context,
        valid_until,
        &source,
        &receipt,
    )?);
    for result in &receipt.case_results {
        observations.push(case_observation(
            context,
            valid_until,
            &source,
            &receipt,
            result,
        )?);
    }

    let bundle = EvidenceBundle {
        schema_version: EVIDENCE_SCHEMA.to_owned(),
        tenant_id: context.tenant_id.to_owned(),
        scope_id: context.scope_id.to_owned(),
        observations,
    };
    bundle.validate()?;

    return Ok(bundle);
}

fn validate_receipt(
    receipt: &AgentEvalReceipt,
    context: &AgentEvalEvidenceContext<'_>,
) -> Result<(), AuditError> {
    if receipt.kind != RECEIPT_KIND {
        return Err(invalid("agentEvalKind", "must be evaluation_receipt"));
    }
    if receipt.schema_version != RECEIPT_SCHEMA {
        return Err(AuditError::UnsupportedVersion(receipt.schema_version.clone()));
    }
    if receipt.repository != context.expected_repository {
        return Err(invalid(
            "agentEvalRepository",
            "receipt repository does not match the requested repository",
        ));
    }
    if receipt.base_sha != context.expected_base_sha {
        return Err(invalid(
            "agentEvalBaseSha",
            "receipt base SHA does not match the requested repository revision",
        ));
    }
    validate_repository(&receipt.repository)?;
    validate_git_sha("agentEvalBaseSha", &receipt.base_sha)?;
    for (field, value) in [
        ("benchmarkSuite", receipt.benchmark_suite.as_str()),
        (
            "benchmarkSuiteVersion",
            receipt.benchmark_suite_version.as_str(),
        ),
        ("harness", receipt.harness.as_str()),
        ("harnessVersion", receipt.harness_version.as_str()),
        ("agent", receipt.agent.as_str()),
        ("model", receipt.model.as_str()),
        ("provider", receipt.provider.as_str()),
        ("environmentIdentity", receipt.environment_identity.as_str()),
        ("toolchainIdentity", receipt.toolchain_identity.as_str()),
    ] {
        validate_text(field, value)?;
    }
    validate_sha256("benchmarkSuiteSha256", &receipt.benchmark_suite_sha256)?;
    validate_sha256("harnessSha256", &receipt.harness_sha256)?;
    validate_sha256("receiptSha256", &receipt.receipt_sha256)?;
    if receipt.case_results.is_empty() || receipt.case_results.len() > MAX_CASE_RESULTS {
        return Err(invalid(
            "agentEvalCaseResults",
            format!("must contain 1..={MAX_CASE_RESULTS} results"),
        ));
    }
    if receipt.result_artifact_sha256.len() > MAX_CASE_RESULTS {
        return Err(invalid(
            "agentEvalResultArtifacts",
            format!("may contain at most {MAX_CASE_RESULTS} digests"),
        ));
    }
    let mut artifact_digests = BTreeSet::new();
    for artifact in &receipt.result_artifact_sha256 {
        validate_sha256("agentEvalResultArtifactSha256", artifact)?;
        if !artifact_digests.insert(artifact) {
            return Err(invalid(
                "agentEvalResultArtifactSha256",
                "contains duplicate artifact digests",
            ));
        }
    }

    let mut case_ids = BTreeSet::new();
    let mut passing = 0_usize;
    let mut executed = 0_usize;
    for result in &receipt.case_results {
        validate_case_result(result)?;
        if !case_ids.insert(&result.case_id) {
            return Err(invalid("agentEvalCaseId", "contains duplicate case IDs"));
        }
        if result.status == AgentEvalCaseStatus::Passed {
            passing += 1;
        }
        if result.status.counts_as_executed() {
            executed += 1;
        }
    }
    let declared = receipt.case_results.len();
    let non_passing = declared.saturating_sub(passing);
    if receipt.declared_case_count != declared
        || receipt.executed_case_count != executed
        || receipt.passing_case_count != passing
        || receipt.non_passing_case_count != non_passing
    {
        return Err(invalid(
            "agentEvalCounts",
            "declared/executed/passing/non-passing counts do not match case_results",
        ));
    }

    let observed_digest = receipt_payload_sha256(receipt)?;
    if observed_digest != receipt.receipt_sha256 {
        return Err(AuditError::Integrity);
    }

    return Ok(());
}

fn validate_case_result(result: &AgentEvalCaseResult) -> Result<(), AuditError> {
    validate_text("agentEvalCaseId", &result.case_id)?;
    if let Some(candidate_tree_sha) = &result.candidate_tree_sha {
        validate_git_sha("agentEvalCandidateTreeSha", candidate_tree_sha)?;
    }
    if let Some(verifier_receipt_sha256) = &result.verifier_receipt_sha256 {
        validate_sha256("agentEvalVerifierReceiptSha256", verifier_receipt_sha256)?;
    }
    if result.status == AgentEvalCaseStatus::Passed
        && (result.candidate_tree_sha.is_none() || result.verifier_receipt_sha256.is_none())
    {
        return Err(invalid(
            "agentEvalPassedCase",
            "passed cases require candidate_tree_sha and verifier_receipt_sha256",
        ));
    }

    return Ok(());
}

fn run_observation(
    context: AgentEvalEvidenceContext<'_>,
    valid_until: i64,
    source: &EvidenceSource,
    receipt: &AgentEvalReceipt,
) -> Result<EvidenceObservation, AuditError> {
    let external_id = digest(&(
        "canonical.agent-eval-run/v1",
        context.tenant_id,
        context.scope_id,
        &receipt.repository,
        &receipt.base_sha,
        &receipt.benchmark_suite_sha256,
        &receipt.harness_sha256,
        &receipt.receipt_sha256,
    ))?;
    let facts = BTreeMap::from([
        ("repository".to_owned(), json!(receipt.repository)),
        ("baseSha".to_owned(), json!(receipt.base_sha)),
        ("benchmarkSuite".to_owned(), json!(receipt.benchmark_suite)),
        (
            "benchmarkSuiteVersion".to_owned(),
            json!(receipt.benchmark_suite_version),
        ),
        (
            "benchmarkSuiteSha256".to_owned(),
            json!(receipt.benchmark_suite_sha256),
        ),
        ("harness".to_owned(), json!(receipt.harness)),
        ("harnessVersion".to_owned(), json!(receipt.harness_version)),
        ("harnessSha256".to_owned(), json!(receipt.harness_sha256)),
        ("agent".to_owned(), json!(receipt.agent)),
        ("model".to_owned(), json!(receipt.model)),
        ("provider".to_owned(), json!(receipt.provider)),
        (
            "environmentIdentity".to_owned(),
            json!(receipt.environment_identity),
        ),
        (
            "toolchainIdentity".to_owned(),
            json!(receipt.toolchain_identity),
        ),
        (
            "declaredCaseCount".to_owned(),
            json!(receipt.declared_case_count),
        ),
        (
            "executedCaseCount".to_owned(),
            json!(receipt.executed_case_count),
        ),
        (
            "passingCaseCount".to_owned(),
            json!(receipt.passing_case_count),
        ),
        (
            "nonPassingCaseCount".to_owned(),
            json!(receipt.non_passing_case_count),
        ),
        ("receiptSha256".to_owned(), json!(receipt.receipt_sha256)),
    ]);

    return Ok(EvidenceObservation {
        external_id,
        evidence_type: "agent_eval.run".to_owned(),
        subject: context.scope_id.to_owned(),
        source: source.clone(),
        collected_at: context.collected_at,
        valid_until,
        facts,
        attestation: None,
    });
}

fn case_observation(
    context: AgentEvalEvidenceContext<'_>,
    valid_until: i64,
    source: &EvidenceSource,
    receipt: &AgentEvalReceipt,
    result: &AgentEvalCaseResult,
) -> Result<EvidenceObservation, AuditError> {
    let external_id = digest(&(
        "canonical.agent-eval-case/v1",
        context.tenant_id,
        context.scope_id,
        &receipt.receipt_sha256,
        &result.case_id,
        result.status.as_str(),
        &result.candidate_tree_sha,
        &result.verifier_receipt_sha256,
    ))?;
    let mut facts = BTreeMap::from([
        ("caseId".to_owned(), json!(result.case_id)),
        ("status".to_owned(), json!(result.status.as_str())),
        ("durationMs".to_owned(), json!(result.duration_ms)),
        ("toolCalls".to_owned(), json!(result.tool_calls)),
        ("retryCount".to_owned(), json!(result.retry_count)),
        (
            "evaluationReceiptSha256".to_owned(),
            json!(receipt.receipt_sha256),
        ),
    ]);
    if let Some(candidate_tree_sha) = &result.candidate_tree_sha {
        facts.insert("candidateTreeSha".to_owned(), json!(candidate_tree_sha));
    }
    if let Some(verifier_receipt_sha256) = &result.verifier_receipt_sha256 {
        facts.insert(
            "verifierReceiptSha256".to_owned(),
            json!(verifier_receipt_sha256),
        );
    }
    if let Some(input_tokens) = result.input_tokens {
        facts.insert("inputTokens".to_owned(), json!(input_tokens));
    }
    if let Some(output_tokens) = result.output_tokens {
        facts.insert("outputTokens".to_owned(), json!(output_tokens));
    }
    if let Some(observed_cost_usd_micros) = result.observed_cost_usd_micros {
        facts.insert(
            "observedCostUsdMicros".to_owned(),
            json!(observed_cost_usd_micros),
        );
    }

    return Ok(EvidenceObservation {
        external_id,
        evidence_type: "agent_eval.case".to_owned(),
        subject: context.scope_id.to_owned(),
        source: source.clone(),
        collected_at: context.collected_at,
        valid_until,
        facts,
        attestation: None,
    });
}

fn receipt_payload_sha256(receipt: &AgentEvalReceipt) -> Result<String, AuditError> {
    let payload = ReceiptPayload {
        kind: &receipt.kind,
        schema_version: &receipt.schema_version,
        repository: &receipt.repository,
        base_sha: &receipt.base_sha,
        benchmark_suite: &receipt.benchmark_suite,
        benchmark_suite_version: &receipt.benchmark_suite_version,
        benchmark_suite_sha256: &receipt.benchmark_suite_sha256,
        harness: &receipt.harness,
        harness_version: &receipt.harness_version,
        harness_sha256: &receipt.harness_sha256,
        agent: &receipt.agent,
        model: &receipt.model,
        provider: &receipt.provider,
        environment_identity: &receipt.environment_identity,
        toolchain_identity: &receipt.toolchain_identity,
        case_results: &receipt.case_results,
        declared_case_count: receipt.declared_case_count,
        executed_case_count: receipt.executed_case_count,
        passing_case_count: receipt.passing_case_count,
        non_passing_case_count: receipt.non_passing_case_count,
        result_artifact_sha256: &receipt.result_artifact_sha256,
    };
    let canonical = digest(&payload)?;
    let Some(raw) = canonical.strip_prefix("sha256:") else {
        return Err(AuditError::Integrity);
    };

    return Ok(raw.to_owned());
}

fn validate_repository(value: &str) -> Result<(), AuditError> {
    let Some((owner, repository)) = value.split_once('/') else {
        return Err(invalid(
            "agentEvalRepository",
            "must use owner/repository form",
        ));
    };
    if repository.contains('/') || !safe_repo_segment(owner) || !safe_repo_segment(repository) {
        return Err(invalid(
            "agentEvalRepository",
            "must use safe owner/repository form",
        ));
    }

    return Ok(());
}

fn safe_repo_segment(value: &str) -> bool {
    return !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
}

fn validate_git_sha(field: &'static str, value: &str) -> Result<(), AuditError> {
    if !matches!(value.len(), 40 | 64) || !is_lower_hex(value) {
        return Err(invalid(field, "must be a lowercase 40- or 64-hex Git SHA"));
    }

    return Ok(());
}

fn validate_sha256(field: &'static str, value: &str) -> Result<(), AuditError> {
    if value.len() != 64 || !is_lower_hex(value) {
        return Err(invalid(field, "must be a lowercase 64-hex SHA-256 digest"));
    }

    return Ok(());
}

fn is_lower_hex(value: &str) -> bool {
    return value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
}

fn validate_text(field: &'static str, value: &str) -> Result<(), AuditError> {
    if value.is_empty()
        || value.len() > MAX_TEXT_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(invalid(
            field,
            format!("must be trimmed text containing 1..={MAX_TEXT_BYTES} bytes"),
        ));
    }

    return Ok(());
}

fn invalid(field: &'static str, reason: impl Into<String>) -> AuditError {
    return AuditError::Invalid {
        field,
        reason: reason.into(),
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_receipt() -> Result<Vec<u8>, AuditError> {
        let mut receipt = AgentEvalReceipt {
            kind: RECEIPT_KIND.to_owned(),
            schema_version: RECEIPT_SCHEMA.to_owned(),
            repository: "elenkos-systems/elenkos-e2e".to_owned(),
            base_sha: "90ad00ab37a89175c766da73f78b1ec92626951e".to_owned(),
            benchmark_suite: "elenkos-agent-eval".to_owned(),
            benchmark_suite_version: "1.0.0".to_owned(),
            benchmark_suite_sha256: "1".repeat(64),
            harness: "elenkos-agent-eval-harness".to_owned(),
            harness_version: "1.0.0".to_owned(),
            harness_sha256: "2".repeat(64),
            agent: "fixture-agent".to_owned(),
            model: "fixture-model".to_owned(),
            provider: "fixture-provider".to_owned(),
            environment_identity: "ubuntu-24.04-x86_64".to_owned(),
            toolchain_identity: "fixture-toolchain-v1".to_owned(),
            case_results: vec![
                AgentEvalCaseResult {
                    case_id: "case.pass".to_owned(),
                    status: AgentEvalCaseStatus::Passed,
                    candidate_tree_sha: Some("3".repeat(40)),
                    verifier_receipt_sha256: Some("4".repeat(64)),
                    duration_ms: 100,
                    tool_calls: 2,
                    retry_count: 0,
                    input_tokens: Some(1_000),
                    output_tokens: Some(200),
                    observed_cost_usd_micros: None,
                },
                AgentEvalCaseResult {
                    case_id: "case.infra".to_owned(),
                    status: AgentEvalCaseStatus::InfraFailed,
                    candidate_tree_sha: None,
                    verifier_receipt_sha256: None,
                    duration_ms: 10,
                    tool_calls: 0,
                    retry_count: 0,
                    input_tokens: None,
                    output_tokens: None,
                    observed_cost_usd_micros: None,
                },
                AgentEvalCaseResult {
                    case_id: "case.skipped".to_owned(),
                    status: AgentEvalCaseStatus::Skipped,
                    candidate_tree_sha: None,
                    verifier_receipt_sha256: None,
                    duration_ms: 0,
                    tool_calls: 0,
                    retry_count: 0,
                    input_tokens: None,
                    output_tokens: None,
                    observed_cost_usd_micros: None,
                },
            ],
            declared_case_count: 3,
            executed_case_count: 2,
            passing_case_count: 1,
            non_passing_case_count: 2,
            result_artifact_sha256: vec!["5".repeat(64)],
            receipt_sha256: String::new(),
        };
        receipt.receipt_sha256 = receipt_payload_sha256(&receipt)?;

        return Ok(serde_json::to_vec(&receipt)?);
    }

    fn context<'a>() -> AgentEvalEvidenceContext<'a> {
        return AgentEvalEvidenceContext {
            tenant_id: "tenant-a",
            scope_id: "organization/acme/system/qa",
            expected_repository: "elenkos-systems/elenkos-e2e",
            expected_base_sha: "90ad00ab37a89175c766da73f78b1ec92626951e",
            collected_at: 1_700_000_000,
            valid_for_seconds: 3_600,
            adapter_version: "canonical-agent-eval-v1",
        };
    }

    #[test]
    fn preserves_run_and_all_case_outcomes() -> Result<(), AuditError> {
        let bundle = agent_eval_receipt_to_evidence(context(), &valid_receipt()?)?;
        bundle.validate()?;
        assert_eq!(bundle.observations.len(), 4);
        assert_eq!(bundle.observations[0].evidence_type, "agent_eval.run");
        let statuses = bundle
            .observations
            .iter()
            .filter(|observation| observation.evidence_type == "agent_eval.case")
            .filter_map(|observation| observation.facts.get("status"))
            .filter_map(serde_json::Value::as_str)
            .collect::<BTreeSet<_>>();
        assert_eq!(statuses, BTreeSet::from(["passed", "infra_failed", "skipped"]));
        Ok(())
    }

    #[test]
    fn rejects_repository_or_base_revision_mismatch() -> Result<(), AuditError> {
        let bytes = valid_receipt()?;
        let mut wrong_repository = context();
        wrong_repository.expected_repository = "other/repository";
        assert!(agent_eval_receipt_to_evidence(wrong_repository, &bytes).is_err());

        let mut wrong_base = context();
        wrong_base.expected_base_sha = "8".repeat(40).leak();
        assert!(agent_eval_receipt_to_evidence(wrong_base, &bytes).is_err());
        Ok(())
    }

    #[test]
    fn rejects_modified_receipt_digest() -> Result<(), AuditError> {
        let bytes = valid_receipt()?;
        let text = String::from_utf8(bytes).map_err(|error| invalid("testFixture", error.to_string()))?;
        let modified = text.replace("fixture-provider", "different-provider");
        assert!(matches!(
            agent_eval_receipt_to_evidence(context(), modified.as_bytes()),
            Err(AuditError::Integrity)
        ));
        Ok(())
    }

    #[test]
    fn rejects_denominator_or_coverage_rewriting() -> Result<(), AuditError> {
        let bytes = valid_receipt()?;
        let text = String::from_utf8(bytes).map_err(|error| invalid("testFixture", error.to_string()))?;
        let modified = text.replace("\"non_passing_case_count\":2", "\"non_passing_case_count\":0");
        assert!(agent_eval_receipt_to_evidence(context(), modified.as_bytes()).is_err());
        Ok(())
    }
}
