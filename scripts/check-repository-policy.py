#!/usr/bin/env python3
"""Hermetic repository policy, provenance, schema, prompt, and CI checks."""

from __future__ import annotations

import json
import re
import sys
import tomllib
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
PINNED_FLAGS2ENV = "4eb9360d418ed64de994e4b1d6e43e7063219e02"
SENSITIVE_FLAG_NAMES = {
    "api-key",
    "bearer-token",
    "credential",
    "password",
    "private-key",
    "secret",
    "token",
}


def fail(message: str) -> None:
    print(f"repository policy violation: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as error:
        fail(f"cannot read {path.relative_to(ROOT)}: {error}")


def load_json(path: Path) -> Any:
    try:
        return json.loads(load_text(path))
    except json.JSONDecodeError as error:
        fail(f"invalid JSON in {path.relative_to(ROOT)}: {error}")


def flag_tables(node: Any) -> list[tuple[str, dict[str, Any]]]:
    result: list[tuple[str, dict[str, Any]]] = []
    if not isinstance(node, dict):
        return result
    flags = node.get("flags")
    if isinstance(flags, dict):
        for name, definition in flags.items():
            if isinstance(definition, dict):
                result.append((name, definition))
    commands = node.get("commands")
    if isinstance(commands, dict):
        for definition in commands.values():
            result.extend(flag_tables(definition))
    return result


def check_flags() -> None:
    try:
        contract = tomllib.loads(load_text(ROOT / ".cli-flags.toml"))
    except tomllib.TOMLDecodeError as error:
        fail(f"invalid .cli-flags.toml: {error}")
    definitions = flag_tables(contract)
    if not definitions:
        fail(".cli-flags.toml declares no flags")
    environments: list[str] = []
    for name, definition in definitions:
        aliases = definition.get("aliases", [])
        exposed = {name, *aliases} & SENSITIVE_FLAG_NAMES
        if exposed:
            fail(f"credential-bearing command-line option declared: {sorted(exposed)}")
        environment = definition.get("env")
        if not isinstance(environment, str) or re.fullmatch(r"[A-Z][A-Z0-9_]+", environment) is None:
            fail(f"flag {name} has no valid environment destination")
        environments.append(environment)
    if len(set(environments)) != len(environments):
        fail("flags reuse an environment destination")

    source = load_text(ROOT / "src" / "cli.rs")
    typed = set(re.findall(r'env\s*=\s*"([A-Z][A-Z0-9_]+)"', source))
    contract_only = {
        "CANONICAL_AUDITOR_HELP_REQUESTED",
        "CANONICAL_AUDITOR_VERSION_REQUESTED",
    }
    if set(environments) - typed - contract_only:
        fail(".cli-flags.toml contains destinations not consumed by the typed CLI")
    if typed - set(environments):
        fail("typed CLI contains environment bindings absent from .cli-flags.toml")

    manifest = load_text(ROOT / "Cargo.toml")
    pattern = re.compile(
        r'flags2env\s*=\s*\{[^}]*rev\s*=\s*"([0-9a-f]{40})"[^}]*\}', re.DOTALL
    )
    match = pattern.search(manifest)
    if match is None or match.group(1) != PINNED_FLAGS2ENV:
        fail("flags2env must remain pinned to the reviewed immutable revision")


def check_program() -> None:
    program = load_json(ROOT / "programs" / "baseline-v1.json")
    if program.get("schemaVersion") != "canonical.assessment-program/v1":
        fail("built-in program has the wrong schema version")
    frameworks = program.get("frameworks", [])
    rules = program.get("rules", [])
    if len(frameworks) < 9 or len(rules) < 35:
        fail("built-in program does not provide broad framework and whole-company coverage")
    identifiers = {item.get("id") for item in frameworks}
    if len(identifiers) != len(frameworks):
        fail("framework identifiers are missing or duplicated")
    for framework in frameworks:
        if not str(framework.get("sourceUrl", "")).startswith("https://"):
            fail("framework is missing authoritative HTTPS provenance")
        if not framework.get("redistribution") or "controlText" in framework:
            fail("framework redistribution metadata is missing or protected text is embedded")
    for rule in rules:
        for mapping in rule.get("frameworkMappings", []):
            if mapping.get("frameworkId") not in identifiers:
                fail("rule mapping references an unknown framework")


def check_prompts() -> None:
    prompt_paths = sorted((ROOT / "prompts").glob("*.md"))
    if len(prompt_paths) < 4:
        fail("the reviewed AI prompt pack is incomplete")
    for path in prompt_paths:
        text = load_text(path).lower()
        for required in ("untrusted", "finding id", "do not"):
            if required not in text:
                fail(f"{path.relative_to(ROOT)} lacks the required {required!r} guardrail")


def check_json_assets() -> None:
    paths = [
        *sorted((ROOT / "schemas").glob("*.json")),
        *sorted((ROOT / "examples").glob("*.json")),
    ]
    if len(paths) < 8:
        fail("schemas or example fixtures are incomplete")
    for path in paths:
        load_json(path)


def check_audit_parity() -> None:
    required = (
        "src/audit.rs",
        "src/engagement.rs",
        "src/package.rs",
        "schemas/audit-engagement-v1.schema.json",
        "schemas/audit-dossier-v1.schema.json",
        "schemas/audit-package-v1.schema.json",
        "examples/dress-rehearsal-engagement.json",
        "docs/parity-matrix.md",
        "tests/audit_workflow.rs",
    )
    for relative in required:
        if not (ROOT / relative).is_file():
            fail(f"audit parity asset is missing: {relative}")

    engagement = load_json(ROOT / "examples" / "dress-rehearsal-engagement.json")
    if engagement.get("schemaVersion") != "canonical.audit-engagement/v1":
        fail("dress rehearsal uses the wrong engagement schema")
    if engagement.get("mode") != "dress_rehearsal":
        fail("the runnable example must exercise dress-rehearsal mode")

    cli = load_text(ROOT / "src" / "cli.rs")
    server = load_text(ROOT / "src" / "server.rs")
    package = load_text(ROOT / "src" / "package.rs")
    for command in ("Audit(AuditArgs)", "Package(PackageArgs)"):
        if command not in cli:
            fail(f"typed CLI is missing {command}")
    for route in ('"/v1/audits"', '"/v1/audit-packages"'):
        if route not in server:
            fail(f"HTTP service is missing {route}")
    for document in (
        "00-audit-report.md",
        "01-control-testing.md",
        "02-evidence-manifest.md",
        "03-evidence-requests.md",
        "04-sampling.md",
        "05-workpaper-index.md",
        "06-findings-and-actions.md",
        "07-audit-trail.md",
        "08-framework-crosswalk.md",
        "audit-dossier.json",
    ):
        if document not in package:
            fail(f"complete audit package is missing {document}")


def check_workflows() -> None:
    workflow_paths = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
    if not workflow_paths:
        fail("no GitHub Actions workflow exists")
    uses_pattern = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)", re.MULTILINE)
    for path in workflow_paths:
        text = load_text(path)
        if re.search(r"permissions:\s*\n\s*contents:\s*read", text) is None:
            fail(f"{path.relative_to(ROOT)} lacks explicit read-only contents permission")
        for reference in uses_pattern.findall(text):
            if reference.startswith("docker://"):
                if "@sha256:" not in reference:
                    fail(f"container action is not digest-pinned: {reference}")
            elif re.fullmatch(r"[^@]+@[0-9a-f]{40}", reference) is None:
                fail(f"action is not commit-pinned: {reference}")


def check_probe_boundaries() -> None:
    python_probe = load_text(ROOT / "probes" / "python" / "runtime_probe.py")
    typescript_probe = load_text(ROOT / "probes" / "typescript" / "runtime-probe.mjs")
    for forbidden in ("subprocess", "shell=True", "eval(", "exec("):
        if forbidden in python_probe:
            fail(f"Python runtime probe contains forbidden execution primitive: {forbidden}")
    for forbidden in ("child_process", "eval(", "new Function("):
        if forbidden in typescript_probe:
            fail(f"TypeScript runtime probe contains forbidden execution primitive: {forbidden}")
    if "no inspected value is emitted" not in python_probe.lower():
        fail("Python probe lacks its value-disclosure invariant")
    if "no inspected value is emitted" not in typescript_probe.lower():
        fail("TypeScript probe lacks its value-disclosure invariant")


def check_no_credentials() -> None:
    patterns = (
        re.compile(r"AKIA[0-9A-Z]{16}"),
        re.compile(r"gh[pousr]_[A-Za-z0-9_]{30,}"),
        re.compile(r"sk-[A-Za-z0-9_-]{30,}"),
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        re.compile(r"eyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}"),
    )
    excluded_parts = {".git", "target", "tmp", "node_modules", "__pycache__"}
    for path in ROOT.rglob("*"):
        if not path.is_file() or excluded_parts.intersection(path.parts):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if any(pattern.search(text) is not None for pattern in patterns):
            fail(f"credential-shaped content detected in {path.relative_to(ROOT)}")


def main() -> None:
    if len(sys.argv) != 1:
        fail("this hermetic checker accepts no command-line options")
    check_flags()
    check_program()
    check_prompts()
    check_json_assets()
    check_audit_parity()
    check_workflows()
    check_probe_boundaries()
    check_no_credentials()
    print("repository policy verified")


if __name__ == "__main__":
    main()
