# canonical-company-auditor.rs

Rust-first whole-company readiness assessment for governance, people, process,
technology, vendors, privacy, data, resilience, and AI risk. The repository provides:

- a deterministic CLI and assessment library;
- a bounded HTTP service with HMAC-signed inbound webhooks;
- Markdown and JSON reports with evidence and program digests;
- reviewed AI prompt packs for summaries, evidence review, gap analysis, and remediation;
- opt-in Python and TypeScript runtime probes that fingerprint possible secret exposure
  without emitting inspected values;
- JSON Schemas, example inputs, negative/property tests, and pinned CI; and
- reference-only overlays for NIST CSF 2.0, NIST SP 800-53 Rev. 5, ISO/IEC 27001:2022,
  SOC 2 Trust Services Criteria, HIPAA Security Rule, GDPR, PCI DSS 4.0.1,
  CIS Controls 8.1, and NIST AI RMF 1.0.

This is a readiness and evidence tool. It does **not** issue certifications, legal
opinions, regulatory determinations, a SOC report, a PCI validation, or an independent
auditor attestation.

## Quick start

Requirements: Rust 1.95, Python 3.11 or newer, and Node.js 20 or newer.

```sh
cargo run -- catalog

cargo run -- validate \
  --manifest examples/company.json \
  --evidence examples/evidence.json

cargo run -- assess \
  --manifest examples/company.json \
  --evidence examples/evidence.json \
  --format markdown \
  --fail-on never
```

`assess` writes to stdout by default. `--output path` uses create-only persistence and
refuses to overwrite an existing report. The default `--fail-on high` still writes the
report, then exits with status 2 when a high or critical failed finding exists. Use
`--fail-on never` when generating an illustrative report in a script.

To create a machine-readable report and a constrained narrative prompt:

```sh
cargo run -- assess \
  --manifest examples/company.json \
  --evidence examples/evidence.json \
  --format json \
  --fail-on never \
  --output report.json

cargo run -- prompt \
  --name remediation-plan \
  --report report.json
```

The prompt command verifies the report ID, manifest digest, summary, findings, and
limitations before rendering. Every serialized report line is prefixed as untrusted
data. Model output is prose only: it cannot become evidence or alter a finding.

## What the engine decides

The built-in program contains Canonical-authored tests. Each test consumes a named,
framework-neutral evidence type and evaluates one bounded scalar condition. Outcomes are:

| Status | Meaning |
| --- | --- |
| `pass` | At least one current, type-compatible observation satisfied the test. |
| `fail` | Current, type-compatible evidence was present and contradicted the test. |
| `unknown` | No current, type-compatible evidence was available. This is an evidence gap, not proof of failure. |

Reports never include normalized fact values. They include content-addressed evidence IDs,
finding IDs, source/program/input digests, Canonical-authored explanations, remediation,
and selected framework reference identifiers.

The assessment is deterministic: the same manifest, evidence bundle, and program produce
the same finding and report IDs. Wall-clock time is not part of evaluation; the manifest's
explicit `assessmentPeriod.endsAt` is the freshness boundary.

## Whole-company baseline

The 20 initial tests cover:

- policy inventory, enterprise risk register, and applicability analysis;
- asset inventory, MFA, and periodic access review;
- data classification, encryption, retention/deletion, and privacy-rights workflows;
- vendor due diligence and contractual safeguards;
- protected change paths and vulnerability remediation;
- logging/detection coverage and incident exercises;
- backup restoration and workforce training;
- runtime secret exposure; and
- AI system inventory and evaluation governance.

The profile is intentionally a strong starting point, not a universal checklist. A real
engagement must tailor scope, materiality, evidence freshness, sampling, regulatory
applicability, complementary controls, and control ownership.

## Framework provenance and licensing

`programs/baseline-v1.json` stores titles, versions, issuing authorities, authoritative
URLs, redistribution classifications, public reference IDs, and Canonical-authored test
language. It does not reproduce protected ISO, AICPA, PCI, or CIS standard text.

Authoritative starting points:

- [NIST Cybersecurity Framework 2.0](https://www.nist.gov/cyberframework)
- [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
- [ISO/IEC 27001:2022](https://www.iso.org/standard/82875.html)
- [AICPA SOC 2 and Trust Services Criteria resources](https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2/)
- [HHS HIPAA Security Rule](https://www.hhs.gov/hipaa/for-professionals/security/index.html)
- [official GDPR text](https://eur-lex.europa.eu/eli/reg/2016/679/oj)
- [PCI DSS](https://www.pcisecuritystandards.org/standards/pci-dss/)
- [CIS Controls v8.1](https://www.cisecurity.org/controls/v8-1)
- [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)

Mappings are directional audit aids; they do not assert that standards are equivalent or
that one Canonical test completely satisfies a cited requirement. Licensed source material
must be obtained and reviewed under its own terms.

## HTTP service and webhooks

Start a loopback development service:

```sh
cargo run -- serve --bind 127.0.0.1:8080
```

Routes:

| Method | Route | Purpose |
| --- | --- | --- |
| `GET` | `/healthz` | Liveness; no tenant data. |
| `GET` | `/v1/catalog` | Reviewed built-in program metadata. |
| `GET` | `/v1/prompts/{name}` | Reviewed prompt template without assessment data. |
| `POST` | `/v1/assessments` | Synchronous deterministic assessment. |
| `POST` | `/v1/webhooks/evidence` | Alias for signed inbound assessment/evidence events. |

POST bodies use this envelope:

```json
{
  "manifest": { "...": "company-manifest-v1" },
  "evidence": { "...": "evidence-bundle-v1" }
}
```

Set `CANONICAL_WEBHOOK_SECRET` to at least 32 bytes to require signatures. The signature is
lowercase hex HMAC-SHA-256 of the exact request body:

```text
X-Canonical-Signature: sha256=<64 lowercase hexadecimal characters>
```

Non-loopback binding fails closed unless that secret is present. Production ingress must
also provide TLS, authenticated tenant claims, rate limiting, replay protection, audit
logging, and durable append-only evidence storage; those are deployment/service boundaries,
not implied by this standalone process.

## Runtime inspection probes

The probes are intentionally separate from the network service. Importing customer code can
run its normal module initialization, so do this only with written authorization in an
isolated, least-privilege container or test environment that has no production credentials
and no unnecessary network access.

Python:

```sh
CANONICAL_PROBE_MODULE=customer_package \
  python3 probes/python/runtime_probe.py > python-probe.json
```

JavaScript/TypeScript (compiled or directly importable module):

```sh
CANONICAL_PROBE_MODULE=./dist/index.js \
  node probes/typescript/runtime-probe.mjs > typescript-probe.json
```

Optional `CANONICAL_PROBE_MAX_BINDINGS` is bounded from 1 through 10,000. The probes:

- never accept command-line options or credential values;
- do not invoke exported callables or property getters;
- bound depth, object count, and per-object properties;
- emit only categories, types, counts, and SHA-256 fingerprints; and
- use conservative secret-pattern heuristics that require human confirmation.

Normalize probe facts into a `runtime.exposure` observation to evaluate the
`runtime.secret-exposure` rule. Never attach the original secret-like value.

## Repository boundaries

```text
manifest + framework-neutral evidence + versioned program
                            |
                            v
                  deterministic Rust engine
                     /                 \
                    v                   v
          JSON / Markdown report    signed HTTP response
                    |
                    v
       constrained AI narrative prompt (prose only)
```

This repository owns the framework-neutral domain, deterministic evaluator, report/package
identity, operator CLI, local service boundary, and initial reference overlays. As the
platform expands:

- reusable live read-only collectors belong in `canonical-evidence-connectors.rs`;
- independently versioned/licensed overlays belong in `canonical-audit-programs`;
- shared service contracts belong in `canonical-interfaces`;
- durable multi-tenant product workflow belongs behind `canonical-web-server.rs` and
  `canonical-api-server.rs`; and
- deployment manifests and Cloudflare policy belong in `canonical-infra` and the cluster
  app-of-apps flow.

No collector or report endpoint performs remediation mutations.

## Schemas and layout

```text
src/                 Rust domain, evaluator, CLI, report, flags, and server
programs/            Reviewed versioned assessment overlays
prompts/             Reviewed AI narrative templates
schemas/             JSON Schema 2020-12 boundaries
probes/python/       Opt-in Python module inspection
probes/typescript/   Opt-in JS/TypeScript module inspection
examples/            Non-sensitive runnable fixtures
tests/               E2E and property conformance
docs/                Architecture and threat-model detail
```

## Validation

```sh
python3 scripts/check-repository-policy.py
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo build --locked --release
CANONICAL_PROBE_SELF_TEST=1 python3 probes/python/runtime_probe.py
CANONICAL_PROBE_SELF_TEST=1 node probes/typescript/runtime-probe.mjs
```

CI repeats policy checks, formatting, strict Clippy, tests, and release builds on Linux,
macOS, and Windows; probe tests and dependency audit run on Linux. GitHub Actions are pinned
to immutable commits or container digests with read-only repository permissions.

## Security

Read [SECURITY.md](SECURITY.md) before reporting a vulnerability and
[THREAT_MODEL.md](THREAT_MODEL.md) before connecting a live tenant or collector. Customer
evidence, credentials, personal data, health data, and runtime values never belong in git.

Licensed under Apache-2.0. This repository is tracked by `DEN-1721`.
