# canonical-company-auditor task runner.

default:
    @just --list

# Run every hermetic repository, Rust, and runtime-probe check.
check:
    python3 scripts/check-repository-policy.py
    cargo fmt --all --check
    cargo clippy --locked --all-targets -- -D warnings
    cargo test --locked --all-targets
    cargo build --locked --release
    CANONICAL_PROBE_SELF_TEST=1 python3 probes/python/runtime_probe.py
    CANONICAL_PROBE_SELF_TEST=1 node probes/typescript/runtime-probe.mjs

# Print the illustrative Markdown assessment without failing on its intentional gaps.
demo:
    cargo run --locked -- assess --manifest examples/company.json --evidence examples/evidence.json --format markdown --fail-on never

# Print reviewed framework metadata.
catalog:
    cargo run --locked -- catalog

# Start the local loopback HTTP service.
serve:
    cargo run --locked -- serve --bind 127.0.0.1:8080

# Run only the value-nondisclosure probe self-tests.
probes:
    CANONICAL_PROBE_SELF_TEST=1 python3 probes/python/runtime_probe.py
    CANONICAL_PROBE_SELF_TEST=1 node probes/typescript/runtime-probe.mjs

# Run the locked dependency advisory check when cargo-audit is installed.
audit:
    cargo audit --deny warnings
