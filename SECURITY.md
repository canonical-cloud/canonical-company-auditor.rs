# Security policy

## Reporting

Do not open a public issue for a suspected vulnerability, leaked credential, customer evidence,
personal data, protected health information, exploit, or signing bypass. Use the repository's
[private vulnerability reporting](https://github.com/canonical-cloud/canonical-company-auditor.rs/security/advisories/new)
workflow. Include the affected commit, component, impact, prerequisites, and the smallest safe
reproduction. Redact all secrets and customer values.

If private reporting is unavailable, contact a canonical-cloud organization owner through an
already established trusted channel. Do not create a new channel by pasting sensitive material
into chat, an issue, a pull request, CI logs, or a repository file.

## Supported versions

Until the first tagged release, only the current `main` branch is supported. After releases begin,
the newest minor release will receive security fixes. Older releases may be fixed when the issue
has exceptional impact, but no long-term-support promise is made here.

## Security invariants

- Evidence collection is read-only; this repository has no remediation mutation endpoint.
- Tenant and scope are explicit and fail closed.
- Reports contain evidence identities and summaries, not normalized evidence values.
- Credentials are environment/secret-store values only and never command-line options.
- Non-loopback HTTP binding requires an HMAC secret of at least 32 bytes.
- Runtime probes emit hashes and counts, never inspected values.
- AI output cannot become evidence or change deterministic findings.
- Output paths are create-only and never silently overwritten.

See [THREAT_MODEL.md](THREAT_MODEL.md) for current boundaries and missing production controls.

## Credential exposure response

If a probe or review detects a probable credential, stop distributing the affected artifact,
preserve only non-sensitive fingerprints and timestamps, and notify the authorized incident owner.
Rotation/revocation is a separate, explicitly authorized operational action. Never print the value
to confirm it, and never copy it into an issue or finding narrative.
