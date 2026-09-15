# Multi-engine readiness evidence pipeline

Canonical Cloud treats account posture scanning as an evidence-collection problem first and a compliance-evaluation problem second.

## Collection lanes

The readiness program has three independent read-only collection lanes:

1. **Native provider adapters** — AWS, GCP, Azure, Cloudflare, GitHub, Upstash, Vercel, DigitalOcean, Netlify, Render, Fly.io, and Heroku. These produce inventory, security-baseline, reliability, utilization, and cost signals through exact allowlisted read operations.
2. **Approved external scanners** — Prowler, ScoutSuite, Trivy, Checkov, Kubescape, kube-bench, kubeaudit, Infracost, and Powerpipe/Steampipe. Canonical invokes only fixed executable/argument grammars; there is no arbitrary shell tool.
3. **Operational telemetry** — fixed Prometheus queries and OpenCost allocation reads for actual CPU, memory, filesystem free-space, scrape health, and Kubernetes cost evidence.

Browser automation is a constrained fallback for console-only visibility. It is not a fourth trust lane and should not replace a provider API when an API exists.

## Trust boundary

Collector output is not a compliance verdict.

`canonical-company-auditor.rs` normalizes the three lanes into `canonical.evidence-bundle/v1` observations. The adapters preserve bounded observed facts and provenance while dropping scanner-authored mutation advice, raw command arguments, stdout/stderr, free-form scanner notes, credentials, and browser state.

External tools cannot directly mark a SOC 2, ISO 27001, NIST, CIS, HIPAA, PCI DSS, or other Canonical control as passed or failed. A Canonical-authored deterministic rule must evaluate normalized evidence against an explicit framework overlay.

## Evidence types

| Lane | Run evidence | Detail evidence |
| --- | --- | --- |
| Native provider | `readiness.run` | `readiness.check`, `readiness.finding` |
| External scanner | `scanner.run` | `scanner.finding` |
| Runtime / FinOps | `operations.readiness_run` | `operations.check`, `operations.finding` |

All observations retain the explicit Canonical tenant and scope supplied by the audit workflow. Provider account/project identifiers are facts, not substitutes for Canonical tenant identity.

## Composition

`evidence_merge::merge_evidence_bundles` composes independent bundles only when schema version, tenant, and scope are identical.

- Output ordering is deterministic.
- Identical repeated observations are collapsed.
- Reuse of the same external evidence identifier for different content fails closed with an integrity error.
- Cross-tenant or cross-scope merging is denied.

This means `native + Prowler + Trivy + Prometheus + OpenCost` can become one deterministic evidence set without making the final report depend on scan execution order.

## Correlation and deduplication

`scanner_signals` computes a time-independent fingerprint for each normalized external scanner finding and can summarize explicit resource-level scanner signals.

A repeated Prowler finding can therefore be recognized across runs. Multiple tools can be shown as corroborating signals on the same resource, but Canonical does **not** assume that similarly worded findings from different tools are semantically equivalent and does not turn tool agreement into a control outcome.

## Freshness

Every evidence observation has `collected_at` and `valid_until`.

- External and native account posture evidence may be valid for at most 30 days at this adapter boundary.
- Operational telemetry may be valid for at most 24 hours because capacity and health signals change quickly.
- Expired or missing evidence must resolve to `unknown`, not `pass`.

Framework-specific rules may require a shorter freshness window.

## Signed API ingestion

The existing Canonical readiness observation API remains the network ingestion boundary. It already provides source identity, tenant/organization matching, HMAC verification, replay sequencing, digest chaining, deduplication/conflict handling, and an explicitly unreviewed substantive state.

Scanner integrations should adapt normalized evidence into that signed ingestion flow rather than creating a second unsigned scanner endpoint.

## Read-only invariants

Collectors and integrations must preserve all of the following:

- no create/update/delete/deploy/restart/scale/secret-write primitives;
- no arbitrary shell command or user-supplied executable;
- no arbitrary PromQL or external URL supplied through MCP parameters;
- bearer-token HTTP clients do not follow redirects;
- response bodies and child-process output are bounded;
- tenant and scope are explicit and never inferred from scanner output;
- secrets, browser storage state, and raw credentials never become evidence;
- remediation is advice only and is executed through a separate, explicit change workflow.

## Recommended scan composition

For a substantial cloud estate, use independent evidence rather than relying on one engine:

- native provider inventory/readiness scan;
- Prowler for broad cloud security and benchmark coverage where supported;
- ScoutSuite or Powerpipe/Steampipe as an independent posture cross-check;
- Trivy and Checkov for repository/IaC policy coverage;
- Kubescape, kube-bench, and kubeaudit for Kubernetes configuration and CIS-style signals;
- Infracost for pre-deploy infrastructure cost estimation;
- OpenCost for observed Kubernetes cost allocation;
- Prometheus for live CPU, memory, filesystem, and target-health evidence.

Not every engine is required for every engagement. The audit plan should record why an engine was included or omitted and should keep unsupported evidence as `unknown` rather than manufacturing parity.
