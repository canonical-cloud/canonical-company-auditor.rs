# Architecture

## Principles

1. Facts are framework-neutral; standards are versioned overlays.
2. Deterministic code decides pass/fail/unknown; AI edits narrative only.
3. Collection is read-only; remediation is a separate capability.
4. Every boundary is versioned, bounded, explicit about tenant/scope, and content-addressed.
5. Missing evidence is uncertainty, not a hidden failure or a hidden pass.
6. Reports preserve limitations and provenance instead of collapsing them into a score.

## Flow

```text
CompanyManifest -------------------+
                                   |
EvidenceBundle -> validate -> seal +--> AssessmentProgram -> evaluate -> AuditReport
                                   |                          |              |
                                   |                          |              +-> JSON
                                   |                          |              +-> Markdown
                                   |                          |              +-> AI prompt
                                   |                          |
                                   +-> tenant/scope/freshness +-> reference mappings

AuditEngagement -> validate references -> requests + samples + workpapers + review
        |                                      |                         |
        +-> lifecycle + actors + milestones    +-> exceptions/responses  |
                                                                          v
AuditReport + sealed evidence index + AuditEngagement ----------------> AuditDossier
                                                                          |
                                                                          +-> full report package
                                                                          +-> integrity manifest
```

`seal_evidence` computes canonical hashes and observation identities from tenant, external ID,
evidence type, subject, source provenance, timestamps, fact digest, and attestation reference.
Nested JSON objects are recursively key-sorted before hashing. Observations are sorted by their
identities, so input order cannot alter a report.

The engine chooses observations by exact `evidenceType`. An observation is current when it was
collected no later than the manifest's assessment end and remains valid through that end. Each
condition returns `true`, `false`, or type-incompatible:

- any current `true` observation makes the test pass;
- otherwise, any current `false` observation makes the test fail; and
- no current compatible observation makes the test unknown.

This aggregation is appropriate for organization-level readiness. Population and sample selection,
auditor exceptions, and reviewer conclusions are separate engagement records rather than hidden
changes to readiness semantics. Programs that need universal quantification or per-system coverage
must add explicit operators and conformance fixtures rather than silently reinterpret a rule.

## Identity model

```text
factsSha256       = SHA-256(canonical facts)
observationId     = SHA-256(provenance + factsSha256)
findingId         = SHA-256(tenant + scope + rule + status + evidenceIds)
manifestSha256    = SHA-256(company manifest)
evidenceSha256    = SHA-256(evidence bundle)
programSha256     = SHA-256(assessment program)
reportId          = SHA-256(all report fields except reportId)
engagementSha256  = SHA-256(audit engagement)
trailEntrySha256  = SHA-256(previous trail digest + event)
dossierId         = SHA-256(engagement + report + control results + indexes + trail)
documentSha256    = SHA-256(exact generated UTF-8 document bytes)
packageId         = SHA-256(dossierId + ordered document metadata)
```

Hashes prove content identity, not authorship. Source signatures and service signing are future
production controls. The optional observation `attestation` is a bounded reference, not a verified
signature in this release.

## HTTP boundary

The Axum server loads one reviewed built-in program at startup. Request bodies are byte-bounded
before JSON extraction. When `CANONICAL_WEBHOOK_SECRET` is set, every POST route requires
`X-Canonical-Signature: sha256=<hex>` over the exact body. HMAC verification uses the library's
constant-time comparison.

`/v1/assessments` and `/v1/webhooks/evidence` evaluate readiness. `/v1/audits` validates a
dress-rehearsal or full-audit engagement and emits a dossier. `/v1/audit-packages` verifies a
dossier and returns the complete in-memory report package. The server remains stateless.

Development loopback may run unsigned. Non-loopback binding requires a signing secret, but that
alone is not production authorization. A production adapter must bind shared-auth service identity
to a tenant and scope, reject replay, enforce quotas, and persist immutable packages.

No HTTP route imports code, runs a command, fetches a URL, calls a model, sends a callback, changes
a customer system, or writes a report to disk.

## Audit engagement boundary

The engagement layer is deliberately separate from observed facts and deterministic rules. It
records objective, criteria, observation period, mode, lifecycle phase, authorized actors,
milestones, evidence requests, sampling, workpapers, exceptions, management responses, recipients,
and ordered events. This permits the same readiness evidence to support an internal rehearsal and
an authorized external audit without confusing tool evidence with auditor judgment.

A finalized full audit fails closed unless every program rule has a completed workpaper, another
actor approved every workpaper, all evidence requests are accepted or closed, every exception has
a management response, milestones are complete, recipients are identified, and an independent
lead or reviewer is recorded. The engine still labels its result a tool conclusion rather than an
attestation.

The CLI package exporter renders ten documents in memory, computes their exact byte counts and
digests, creates a new directory, and uses create-only file writes. The manifest binds ordered
document metadata to the dossier. It is therefore possible to detect a changed report document
without placing raw normalized evidence values in the package.

## AI boundary

AI prompt templates are version-controlled assets. Before a prompt is rendered, a deserialized
report is reverified. The report contains no normalized facts. Each physical JSON line receives a
`DATA ` prefix between explicit untrusted-data markers. Templates require finding/evidence
citations and prohibit status changes, invented evidence, protected-standard reconstruction, legal
conclusions, and certification language.

A production model adapter should add structured output schema validation, provider retention and
training controls, tenant-approved model selection, prompt/output logging with redaction, and
evaluation against prompt injection and unsupported claims. Model prose is never written back into
the evidence bundle.

## Runtime probe boundary

Python and TypeScript probes are optional tools for an authorized customer test environment. They
reject argv and consume only documented environment configuration. Both execute an explicit module
import, then inspect exported/module binding data with bounded traversal. They avoid callables and
getters and emit only type/category/count data plus SHA-256 fingerprints.

Module import can run arbitrary initialization. The safe production shape is an ephemeral worker
with an immutable signed image, no production credentials, read-only source/input, a writable
scratch volume, CPU/memory/time limits, no privilege escalation, seccomp, and deny-by-default
network policy. That worker is intentionally not implemented by the local HTTP server.

## Extension rules

### New framework

Add metadata only after confirming version, issuing authority, authoritative HTTPS source,
redistribution terms, and revision status. Map only public reference identifiers. A mapping means
the Canonical-authored test may contribute evidence to review of that reference; it is not a claim
of equivalence or complete satisfaction.

### New rule

Use a framework-neutral evidence type, one supported deterministic operator, bounded expected
value, Canonical-authored title/remediation, and reviewed references. Add fixtures for pass, fail,
unknown, stale evidence, wrong types, tenant mismatch, and report determinism. New operators require
cross-language semantics before release.

### New collector

Collectors belong in `canonical-evidence-connectors.rs`. They must be read-only, least-privilege,
tenant/scope bound, paginated and quota-aware, explicit about freshness, and deterministic after
normalization. Never place remediation APIs in a collection adapter.

### New output

Keep the internal domain stable and build an explicit verified boundary projection. External
formats such as OSCAL must not become the internal model. Preserve all digests and limitations.
