# Agent guidelines — canonical-company-auditor.rs

This repository is the Rust-first whole-company audit engine tracked by `DEN-1721`.
It produces readiness findings and evidence packages; it never represents its output
as a certification, legal opinion, or independent auditor attestation.

## Boundaries

- Keep observed facts framework-neutral. Standards metadata and references are overlays.
- Never reproduce licensed standards text. Canonical-authored tests may cite public
  identifiers and authoritative source URLs.
- Treat manifests, evidence, webhook bodies, runtime-probe output, and AI output as
  untrusted input.
- Evidence collection is read-only. Remediation mutations require a separate system and
  explicit authorization.
- Tenant and hierarchical scope are required on every assessment. Never infer a tenant.
- Reports identify absent evidence as `unknown`, not `fail`, and never turn AI prose into
  evidence.
- Runtime probes must emit fingerprints and metadata, never raw secrets or customer values.
- Customer-code import is opt-in, locally initiated, bounded, and never available from an
  unauthenticated server route.
- Webhook secrets and model credentials are environment/secret-store values only.

## Command-line contract

- Every binary invocation audits and applies the repository-root `.cli-flags.toml` through
  the pinned `flags2env` binding before Clap performs typed parsing.
- Unknown flags, unknown commands, malformed values, and unexpected positionals fail closed.
- Credentials are never command-line options.
- stdout is reserved for requested output; diagnostics and logs go to stderr.

## Verification

Run all of the following before publication:

```sh
python3 scripts/check-repository-policy.py
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo build --locked --release
CANONICAL_PROBE_SELF_TEST=1 python3 probes/python/runtime_probe.py
CANONICAL_PROBE_SELF_TEST=1 node probes/typescript/runtime-probe.mjs
```

## Workspace instructions

The master workspace instructions are available at `~/codes/AGENTS.md` and at
`.ores/agents/AGENTS.md` when the local link has been installed. They govern git,
GitHub identity, credential handling, explicit-path staging, synchronization, and PRs.
