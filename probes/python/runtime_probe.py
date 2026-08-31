#!/usr/bin/env python3
"""Opt-in Python runtime exposure probe that never emits inspected values."""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import re
import sys
from collections import deque
from collections.abc import Mapping
from dataclasses import dataclass
from types import ModuleType
from typing import Any

PROBE_VERSION = "1.0.0"
SCHEMA_VERSION = "canonical.runtime-probe/v1"
MODULE_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]{0,159}$")
SENSITIVE_NAME = re.compile(
    r"(?:api[_-]?key|auth|bearer|credential|passwd|password|private[_-]?key|secret|session|token)",
    re.IGNORECASE,
)
SECRET_VALUE_PATTERNS = (
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}"),
    re.compile(r"sk-[A-Za-z0-9_-]{20,}"),
    re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
)


@dataclass(frozen=True)
class Fingerprint:
    """Non-reversible metadata for one possible exposure."""

    category: str
    location_sha256: str
    value_sha256: str | None
    value_type: str


@dataclass(frozen=True)
class ProbeResult:
    """Bounded probe output safe for later evidence normalization."""

    schema_version: str
    runtime: str
    probe_version: str
    target: str
    facts: dict[str, int | bool]
    fingerprints: tuple[Fingerprint, ...]
    limitations: tuple[str, ...]


def _digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _looks_secret(value: str) -> bool:
    if len(value) > 16_384:
        return False
    return any(pattern.search(value) is not None for pattern in SECRET_VALUE_PATTERNS)


def inspect_bindings(target: str, bindings: Mapping[str, Any], maximum: int) -> ProbeResult:
    """Inspect inert containers and strings without invoking properties or callables."""

    queue: deque[tuple[str, Any, int]] = deque(
        (f"module.{name}", value, 0)
        for name, value in sorted(bindings.items())
        if not name.startswith("__")
    )
    seen: set[int] = set()
    fingerprints: list[Fingerprint] = []
    scanned = 0
    truncated = False

    while queue:
        if scanned >= maximum:
            truncated = True
            break
        location, value, depth = queue.popleft()
        scanned += 1
        identity = id(value)
        if identity in seen:
            continue
        seen.add(identity)

        leaf_name = location.rsplit(".", 1)[-1]
        name_match = SENSITIVE_NAME.search(leaf_name) is not None
        value_match = isinstance(value, str) and _looks_secret(value)
        if name_match or value_match:
            fingerprints.append(
                Fingerprint(
                    category="secret_like_value" if value_match else "sensitive_binding_name",
                    location_sha256=_digest(location),
                    value_sha256=_digest(value) if value_match else None,
                    value_type=type(value).__name__,
                )
            )

        if depth >= 4 or isinstance(value, (str, bytes, bytearray)):
            continue
        if type(value) is dict:
            for index, (key, nested) in enumerate(list(value.items())[:256]):
                queue.append((f"{location}.key:{index}", key, depth + 1))
                queue.append((f"{location}.value:{index}", nested, depth + 1))
        elif type(value) in (list, tuple):
            for index, nested in enumerate(value[:256]):
                queue.append((f"{location}.item:{index}", nested, depth + 1))

    fingerprints.sort(key=lambda item: (item.category, item.location_sha256))
    return ProbeResult(
        schema_version=SCHEMA_VERSION,
        runtime="python",
        probe_version=PROBE_VERSION,
        target=target,
        facts={
            "suspected_secret_count": len(fingerprints),
            "scanned_binding_count": scanned,
            "truncated": truncated,
        },
        fingerprints=tuple(fingerprints),
        limitations=(
            "Importing the target may execute its normal module initialization; run only in an authorized isolated environment.",
            "The probe inspects module globals and inert containers only; it does not invoke callables, descriptors, or properties.",
            "Fingerprints are heuristics and require human validation; no inspected value is emitted.",
        ),
    )


def inspect_module(module_name: str, maximum: int = 5_000) -> ProbeResult:
    """Explicitly import and inspect one allow-named customer module."""

    if MODULE_PATTERN.fullmatch(module_name) is None:
        raise ValueError("module name must be a dotted Python identifier")
    if not 1 <= maximum <= 10_000:
        raise ValueError("maximum must be between 1 and 10000")
    module: ModuleType = importlib.import_module(module_name)
    return inspect_bindings(module_name, vars(module), maximum)


def to_wire(result: ProbeResult) -> dict[str, Any]:
    """Project the internal immutable result into the shared camelCase JSON contract."""

    return {
        "schemaVersion": result.schema_version,
        "runtime": result.runtime,
        "probeVersion": result.probe_version,
        "target": result.target,
        "facts": result.facts,
        "fingerprints": [
            {
                "category": item.category,
                "locationSha256": item.location_sha256,
                "valueSha256": item.value_sha256,
                "valueType": item.value_type,
            }
            for item in result.fingerprints
        ],
        "limitations": list(result.limitations),
    }


def _self_test() -> None:
    secret = "sk-" + ("a" * 32)
    result = inspect_bindings("self_test", {"safe": 1, "api_token": secret}, 100)
    encoded = json.dumps(to_wire(result), sort_keys=True)
    assert result.facts["suspected_secret_count"] == 1
    assert secret not in encoded
    print(json.dumps({"ok": True, "probeVersion": PROBE_VERSION}, sort_keys=True))


def main() -> int:
    """Environment-only executable boundary; argv is intentionally unsupported."""

    if len(sys.argv) != 1:
        print("runtime-probe: command-line options are not supported; use documented environment keys", file=sys.stderr)
        return 2
    if os.environ.get("CANONICAL_PROBE_SELF_TEST") == "1":
        _self_test()
        return 0
    module_name = os.environ.get("CANONICAL_PROBE_MODULE")
    if module_name is None:
        print("runtime-probe: CANONICAL_PROBE_MODULE is required", file=sys.stderr)
        return 2
    maximum_text = os.environ.get("CANONICAL_PROBE_MAX_BINDINGS", "5000")
    try:
        maximum = int(maximum_text)
        result = inspect_module(module_name, maximum)
    except (ImportError, TypeError, ValueError) as error:
        print(f"runtime-probe: probe failed: {type(error).__name__}", file=sys.stderr)
        return 1
    print(json.dumps(to_wire(result), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
