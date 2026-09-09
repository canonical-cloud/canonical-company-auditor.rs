#!/usr/bin/env python3
"""Hermetic guard for the readiness peer-authority/TJSV CI contract."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TJSV_SHA = "2281843126ab644607b11cf8281d84f382d68dfc"
EXPECTED_DEFS = {
    "DateString",
    "FrameworkId",
    "Identifier",
    "ReadinessAnswer",
    "ReadinessContext",
    "ReadinessResponse",
    "ReadinessStatus",
}


def fail(message: str) -> None:
    raise SystemExit(f"readiness contract policy violation: {message}")


def text(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def main() -> None:
    typespec = text("readiness/contract/main.tsp")
    schema = json.loads(text("readiness/response.schema.json"))
    workflow = text(".github/workflows/ci.yml")
    ignored = text(".gitignore")

    if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        fail("authored schema must remain Draft 2020-12")
    if schema.get("$ref") != "ReadinessResponse":
        fail("authored schema root must resolve through ReadinessResponse")
    if set(schema.get("$defs", {})) != EXPECTED_DEFS:
        fail("authored schema declaration inventory drifted")

    if "namespace CanonicalReadiness;" not in typespec:
        fail("TypeSpec authority must keep the canonical namespace")
    for declaration in EXPECTED_DEFS:
        if f'@id("{declaration}")' not in typespec:
            fail(f"TypeSpec authority is missing stable id {declaration}")

    required_uses = (
        f"ORESoftware/typespec-json-schema-validator@{TJSV_SHA}",
        f"ORESoftware/typespec-json-schema-validator/actions/verify-contract-ir@{TJSV_SHA}",
        f"ORESoftware/typespec-json-schema-validator/actions/test-consumer-admission@{TJSV_SHA}",
    )
    for reference in required_uses:
        if reference not in workflow:
            fail(f"CI is missing immutable TJSV gate {reference}")
    for required in (
        "readiness/contract/main.tsp",
        "readiness/response.schema.json",
        "readiness/contract/instances",
        ".typespec-json-schema-validator/readiness-contract-ir.json",
        ".typespec-json-schema-validator/readiness-consumer-verification.json",
    ):
        if required not in workflow:
            fail(f"CI is missing readiness contract input/evidence {required}")

    valid = sorted((ROOT / "readiness/contract/instances/ReadinessResponse/valid").glob("*.json"))
    invalid = sorted((ROOT / "readiness/contract/instances/ReadinessResponse/invalid").glob("*.json"))
    if len(valid) < 2 or len(invalid) < 3:
        fail("instance corpus lost required positive/negative coverage")
    for path in [*valid, *invalid]:
        json.loads(path.read_text(encoding="utf-8"))

    if ".typespec-json-schema-validator/" not in ignored:
        fail("generated TJSV evidence directory must stay untracked")

    print("readiness TypeSpec/JSON Schema peer-authority policy verified")


if __name__ == "__main__":
    main()
