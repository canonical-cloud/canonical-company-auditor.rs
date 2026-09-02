# Audit and readiness parity matrix

This matrix defines practical parity for the Canonical whole-company audit stack. It is
based on publicly documented capabilities in Vanta Audits, Drata Audit Hub and Evidence
Library, Secureframe Audit and Data Room workflows, and AuditBoard audit management. It
does not copy proprietary implementation details, control text, or licensed content.

Primary comparison sources:

- [Vanta Audits](https://help.vanta.com/en/collections/12575269-audits)
- [Drata Audit Hub](https://drata.com/products/compliance/audit-hub)
- [Drata Evidence Library](https://help.drata.com/en/articles/13404035-evidence-overview)
- [Drata internal audits](https://help.drata.com/en/articles/13893566-internal-audits-in-drata-new-experience)
- [Secureframe automated evidence collection](https://secureframe.com/features/automated-evidence-collection)
- [Secureframe audit readiness and data room](https://support.secureframe.com/en/articles/15111484-faqs-data-room-and-audit-readiness-access-timing-and-evidence)
- [AuditBoard audit management overview](https://go.auditboard.com/rs/961-ZQV-184/images/AB-EB-AuditBoard-Audit-Management-Elevating-Audit-for-Strategic-Impact.pdf)

## Capability contract

| Capability | Parity requirement | Status in this repository |
| --- | --- | --- |
| Continuous readiness | Current evidence, expiration, deterministic tests, gaps, severity, and CI thresholds | Implemented |
| Dress rehearsal | Internal audit using the same request, sampling, workpaper, review, exception, and reporting model as a full audit | Implemented |
| Full audit engagement | Observation window, criteria, scope, actors, independence, lifecycle phases, milestones, and recipients | Implemented |
| Shared control model | Framework-neutral facts and tests reused across framework overlays | Implemented |
| Multi-framework coverage | GDPR, HIPAA, NIST CSF, NIST 800-53, NIST AI RMF, SOC 2, ISO 27001, PCI DSS, and CIS | Implemented with public reference mappings |
| Custom controls | Versioned JSON assessment programs with deterministic operators | Implemented |
| Evidence library | Tenant/scope boundary, provenance, current-through date, source version, content digest, and reusable mapping | Implemented as portable bundles and dossier indexes |
| Evidence versions | Immutable content-addressed observations and package snapshots | Implemented |
| Evidence requests | Owner, due date, status, mapped controls, evidence attachments, and reviewer note | Implemented |
| Auditor collaboration | Engagement-scoped actors, evidence requests, review decisions, and audit trail | Implemented as API/CLI contracts; interactive UI is outside this engine |
| Population sampling | Population identity and size, method, selected fingerprints, rationale, and workpaper linkage | Implemented |
| Workpapers | Procedure performed, preparer, design and operating conclusions, evidence citations, sample, and exceptions | Implemented |
| Independent review | Reviewer/preparer separation, approval or changes requested, review time, and note | Implemented and fail-closed for finalized audits |
| Exceptions | Observation/minor/major classification, factual description, evidence, and disposition | Implemented |
| Management responses | Owner, response, action plan, due date, and status | Implemented; mandatory for every finalized exception |
| Audit history | Ordered events and a digest chain binding every event to its predecessor | Implemented |
| Point-in-time packages | Frozen dossier, report, testing matrix, evidence manifest, requests, sampling, workpapers, actions, trail, and crosswalk | Implemented with a package integrity manifest |
| AI narrative | Constrained executive, evidence, gap, and remediation prompts over verified reports | Implemented; AI cannot change evidence or findings |
| Runtime inspection | Opt-in Python and TypeScript import/reflection with bounded, value-free results | Implemented |
| Connector ecosystem | Read-only collection from cloud, identity, HR, ticketing, code, device, database, and vendor systems | Adapter boundary implemented; individual connectors belong in `canonical-evidence-connectors.rs` |
| Persistent multi-user portal | Durable storage, identity-based RBAC, comments, notifications, dashboards, and auditor data room | HTTP contracts implemented; application and storage layer belong in the web/API server repositories |
| Policy authoring | Policy templates, owners, approvals, employee acceptance, and renewal workflows | Evidence tests implemented; authoring workflow belongs in a dedicated policy application |
| Risk and vendor registers | Create, approve, monitor, and remediate risks and vendors | Audit tests implemented; system-of-record mutations remain outside this read-only audit engine |
| Trust center and questionnaires | External security profile and response automation | Outside the audit-engine boundary |

## Mode semantics

### Readiness

`assess` is a continuous, deterministic preparation check. It does not require auditor
workpapers. Missing, stale, out-of-scope, or type-incompatible evidence is `unknown`, not a
failed control. Its report answers: "What is ready, what appears contradicted, and what
evidence is still missing?"

### Dress rehearsal

`audit` with `mode: dress_rehearsal` exercises the complete audit workflow without claiming
external independence. It may remain in any lifecycle phase and can intentionally contain
open requests, incomplete tests, unreviewed workpapers, and missing responses. Its report
answers: "If the audit started now, where would fieldwork or review stop?"

### Full audit

`audit` with `mode: full_audit` supports an authorized auditor. A finalized engagement is
rejected unless every program rule has a completed workpaper, every workpaper is approved by
someone other than its preparer, every evidence request is accepted or closed, every
exception has a management response, all milestones are complete, recipients are named, and
an independent audit lead or reviewer is recorded.

The resulting conclusion is explicitly a tool conclusion. Only an authorized, qualified
auditor can determine whether the evidence, procedures, samples, and conclusions are
sufficient and issue any certification, attestation, or legal opinion.

## Package contents

Every package contains:

1. Primary audit engagement report
2. Control testing matrix
3. Evidence manifest and custody index
4. Evidence request register
5. Population and sample register
6. Workpaper and review index
7. Findings, exceptions, and management actions
8. Content-addressed audit trail
9. Framework crosswalk
10. Machine-readable audit dossier
11. Package manifest with exact byte counts and SHA-256 digests

The CLI refuses an existing output directory and every file is created with create-only
semantics. Re-exporting changed data therefore produces a new package instead of silently
rewriting the previous audit snapshot.
