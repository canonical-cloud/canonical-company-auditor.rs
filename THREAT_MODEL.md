# Threat model

## Assets

- tenant identity and hierarchical assessment scope;
- customer system, workforce, vendor, data, and governance metadata;
- evidence provenance, collection time, freshness, normalized facts, and attestations;
- immutable finding, report, engagement, dossier, trail, document, and package identifiers;
- auditor identities, evidence requests, samples, workpapers, exceptions, reviews, and
  management responses;
- webhook signing material and future connector/model credentials; and
- the separation between deterministic evidence decisions and AI-authored narrative.

## Trust boundaries

1. Company manifests, evidence JSON, custom programs, engagement records, deserialized reports
   and dossiers, webhook bodies, runtime modules, runtime probe output, and model output are
   untrusted.
2. The CLI process receives local filesystem authority from its operator. Output files are
   create-only, but input access control and disk encryption belong to the host.
3. The HTTP process authenticates only a shared HMAC at this stage. A valid signature proves
   possession of the secret, not a user identity, tenant entitlement, freshness, or replay
   uniqueness.
4. Importing a customer module crosses into customer code and can execute its normal module
   initialization. The probe must run in an authorized disposable environment.
5. Framework mappings are reviewable overlays. They are not internal evidence facts and do
   not create a certification conclusion.
6. An AI model is a narrative consumer, never a control evaluator, evidence source, or
   authorization authority.

## Threats and implemented controls

| Threat | Implemented control | Production follow-up |
| --- | --- | --- |
| Cross-tenant evidence injection | Exact tenant equality plus segment-aware hierarchical scope checks | Bind tenant/scope to verified shared-auth claims and enforce equivalent database row policy |
| Prefix-confused scope escalation | A scope contains only itself or a `/`-delimited descendant | Add shared cross-language authorization fixtures |
| Evidence/report tampering | Canonical JSON SHA-256 identities; reports verify manifest, summary, findings, limitations, and report ID before prompting | Sign collector attestations and package manifests with rotating service keys |
| Dossier or package tampering | Dossiers bind the engagement, readiness report, results, indexes, exceptions, trail, and limitations; packages verify every exact document byte and ordered manifest entry | Sign finalized package manifests with an auditor or service identity and retain them in immutable storage |
| Forged engagement role | Engagement actors and independence are explicit and internally referenced; no identity is inferred | Resolve actor IDs and independence from shared-auth and an approved auditor directory |
| Self-review | Reviewer and preparer must differ; finalized workpapers require approval | Enforce organization-specific independence and conflict checks in the identity layer |
| Incomplete record presented as final | Finalization requires all controls tested and approved, requests accepted/closed, milestones complete, recipients named, and every exception answered | Require authorized electronic signatures and immutable finalization transactions |
| Sample identifier disclosure | Samples contain only SHA-256 fingerprints of selected item identifiers | Retain the re-identification map only in the restricted auditor data room |
| Stale evidence presented as current | `collectedAt <= assessment end <= validUntil` is required for rule evaluation | Add rule-specific freshness and sampling policies |
| Missing evidence treated as failure | Missing, stale, or type-incompatible evidence is `unknown`, never `fail`; engagement workpapers separately document sufficiency decisions | Add rule-specific evidence-quality and population-completeness policies |
| Memory/request amplification | 10 MiB CLI input cap, configurable 1 KiB–10 MiB HTTP cap, 10,000 observations, 64 KiB facts per observation, bounded fact keys | Add per-tenant quotas, concurrency limits, and ingress rate limits |
| Arbitrary remote code execution | Network service exposes no customer-code execution route | Keep execution out of the service; use ephemeral isolated workers with allowlisted immutable images if later required |
| Customer-code side effects | Runtime import is opt-in, local, documented as executable, and absent from server routes | Enforce container sandbox, read-only filesystem, no secrets, network deny, CPU/memory/time limits, and signed probe image |
| Secret disclosure by probes | No raw inspected value or property name is emitted; values and locations become SHA-256 fingerprints; traversal is bounded and getter/callable invocation is avoided | Store only reviewed normalized output; rotate any confirmed credential through a separate authorized process |
| Prompt injection through evidence | Deterministic report excludes raw facts; prompt marks every serialized line as untrusted and forbids instruction following | Use structured model output, output validation, model/provider data controls, and continuous prompt-injection evaluation |
| AI invents or changes findings | Prompt must preserve status and cite finding/evidence IDs; verified report remains source of truth | Reject narrative claims that cannot be resolved to immutable IDs |
| Webhook forgery | Optional HMAC-SHA-256 over exact bytes; non-loopback bind requires a 32-byte-or-longer secret; verification is constant-time through the HMAC library | Use shared-auth service identity, secret rotation, mTLS where appropriate, and per-tenant keys |
| Webhook replay | No misleading replay claim is made | Require signed timestamp and nonce/idempotency key with a durable replay window before production ingress |
| SSRF | No outbound callback, URL fetch, redirect, or arbitrary connector endpoint exists | Apply destination allowlists and DNS/IP revalidation to any future connector transport |
| Overwrite/rollback | CLI report and package output use create-new semantics; the package directory must not exist | Use append-only versioned object storage, retention lock, and a monotonic assessment ledger |
| Licensed standard leakage | Program stores only metadata, public reference IDs, authoritative URLs, and Canonical-authored language | Review overlay licensing and provenance independently before each release |
| False certification claim | Every report contains fixed limitations; full-audit support still emits only a tool conclusion; docs distinguish workflow support from an auditor's opinion | Require qualified-auditor signatures and approved product language at delivery boundaries |
| CI supply-chain mutation | Actions use immutable commit/digest pins, read-only repository permission, locked dependencies, strict policy checks | Add artifact provenance, SBOM, signing, protected environments, and dependency update review |

## Deliberate non-goals in this repository

This repository does not provide user authentication, identity-backed role enforcement, database
row-level security, encrypted evidence storage, external connector transports, outbound webhooks,
replay storage, distributed queues, a browser UI, automatic remediation, model-provider calls,
certification issuance, legal interpretation, or auditor sampling judgment. It records sampling
and workpaper decisions supplied by authorized users but does not decide whether they are
professionally sufficient.

Those controls depend on the deployment identity and on adjacent Canonical repositories. Their
absence is a hard production boundary, not an invitation to emulate them with hidden defaults.

## Abuse-resistant operating procedure

1. Obtain written authorization naming the tenant, scope, systems, data classes, period,
   collectors, runtime modules, and allowed execution environment.
2. Start with read-only connector scopes and no customer-code execution.
3. Normalize and review evidence before assessment; never commit customer data.
4. Run runtime probes only when needed, in a disposable sandbox with no production secrets or
   unnecessary network access.
5. Treat every `unknown` as a collection/reviewer decision and every `fail` as a candidate
   finding requiring corroboration and materiality review.
6. Use a dress rehearsal to close evidence requests, complete sampling and workpapers, separate
   preparation from review, and obtain management responses before the external observation window.
7. Deliver the deterministic report, dossier, package manifest, and digests alongside, not
   replaced by, any AI-authored narrative.
8. Route changes, rotations, deletions, or remediation into a separately authorized workflow.
