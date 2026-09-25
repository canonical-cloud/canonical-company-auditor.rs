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

## Repository-local Git worktrees

- Create or use a Git worktree only when the human operator explicitly authorizes it for the current task. Concurrency or a dirty checkout is not permission by itself.
- Put every authorized worktree at `<repository-root>/tmp/worktrees/<name>`; from the repository root, use `./tmp/worktrees/<name>`. Never place worktrees beside repositories or organization directories.
- Keep `tmp`, `temp`, `tmp/worktrees`, and `temp/worktrees` ignored in the repository-root `.gitignore`. Do not commit files from those directories.
- Relocate or remove a worktree only when the operator explicitly requests it. Before removal, preserve and publish intended changes, verify its commit is represented on the target branch, and confirm there are no tracked, untracked, ignored-sensitive, or in-use files that must survive. Remove it with `git worktree remove <path>` without `--force`; never delete a worktree directory with `rm`.

<!-- BEGIN ores-agents-pointer: managed by ORESoftware/my-ai; edit there, not here -->

## Canonical agent instructions

Before doing anything else in this repository, also read:

    .ores/agents/AGENTS.md

That path is a symlink to `~/codes/oresoftware/my-ai/AGENTS.md`, whose canonical copy is
<https://github.com/ORESoftware/my-ai/blob/main/AGENTS.md>.

It exists at a fixed path *inside* the repository because some agents cannot walk up past
the repository root, so machine-wide instructions one or more directories above are
invisible to them. This pointer plus that path make the same file reachable from a working
directory anywhere in the tree.

The symlink is deliberately **not committed**: it names an absolute path that is only valid
on a machine with `~/codes/oresoftware/my-ai` checked out, so committing it would produce a
broken link for everyone else and for CI. `.ores/` is git-ignored for that reason. If
`.ores/agents/AGENTS.md` is missing on your machine, create it with:

    mkdir -p .ores/agents
    ln -sfn "$HOME/codes/oresoftware/my-ai/AGENTS.md" .ores/agents/AGENTS.md

or run `~/codes/oresoftware/my-ai/scripts/link-repo-agents.sh` once to do it for every git
repository under `~/codes`, and `--check` to verify them.

A missing `.ores/agents/AGENTS.md` is a setup gap on the reader's machine, never a reason to
skip the canonical instructions: fetch them from the URL above instead.

<!-- END ores-agents-pointer -->
