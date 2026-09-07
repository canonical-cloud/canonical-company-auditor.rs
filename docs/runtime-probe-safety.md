# Runtime probe v1.1 safety and execution contract

The JavaScript/TypeScript probe remains an opt-in, locally initiated evidence aid, not a vulnerability scanner, sandbox, or compliance verdict. Its observations never automatically answer a readiness question.

## Invocation

```sh
CANONICAL_PROBE_ALLOW_IMPORT=1 \
CANONICAL_PROBE_MODULE=./approved/customer-module.mjs \
CANONICAL_PROBE_MAX_BINDINGS=5000 \
CANONICAL_PROBE_TIMEOUT_MS=5000 \
node probes/typescript/runtime-probe.mjs
```

`CANONICAL_PROBE_ALLOW_IMPORT=1` is newly required. Obtain written scope and permission first. Module initialization executes code and can perform writes, network requests, start subprocesses, or read inherited environment variables. Run in a disposable OS/container sandbox with read-only input mounts, restricted credentials and networking, resource limits, and whole-container cleanup. The Node subprocess is NOT that sandbox and does not terminate every possible descendant. Never expose this importer as a web route.

Only an explicit local path (`./`, `../`, an absolute path, or a file URL without query/fragment) is accepted. Package names, data URLs and network URLs are rejected. The emitted target is a SHA-256 identifier, not the path. Numeric limits must be whole positive decimal numbers: maximum bindings 1–10000, timeout 1–30000 milliseconds. No command-line options are accepted by this script; the main Rust auditor retains its flags-2-env contract.

## Observation and process boundaries

Own property descriptors are traversed without invoking accessors. Nested field names remain available to the detector internally but only path hashes are emitted. Aliased objects are checked for sensitive names at each binding. Cycles are bounded. The queue is bounded by the binding limit, depth is limited to four, and each object contributes at most 256 string-keyed properties. Accessors, non-metadata symbols, descriptor errors, oversized strings, and traversal limits mark the result incomplete. Proxy traps can still execute; enumeration and user initialization are bounded by the subprocess deadline, not by a false claim of side-effect-free reflection.

The launcher uses a fixed Node executable and a fixed internal entrypoint, without a shell. It captures operating-system stdout/stderr pipes (including native file-descriptor writes), discards customer output, caps it at 64 KiB, caps the separate result channel at 4 MiB, applies a Node heap limit, and terminates on the deadline. The result channel is untrusted and reconstructed from allowlisted metadata. No child error object, stack, filename, or arbitrary extra field is reflected. Node preload options are not inherited into the child. Other environment variables are inherited: provision only what the approved test actually needs.

The child-process policy exception is confined to this fixed launcher. It replaces in-process customer initialization; it does not authorize shell commands or general subprocess evidence collectors.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | An observation was produced with no recorded truncation, or the synthetic self-test passed. This is not a clean bill of health. |
| 1 | No trustworthy observation: missing import authorization, invalid input, deadline, process error, or invalid/oversized output. |
| 2 | Unsupported command-line arguments. |
| 3 | An observation was produced, but inspection was incomplete. Treat uncovered areas as unknown. |

Fingerprint hashes remain sensitive evidence and are not anonymization. Limit access and retention. A heuristic match requires human investigation; an absence of matches does not prove an absence of secrets. The Python probe is unchanged by this JavaScript-specific hardening and must not be described as having these subprocess guarantees.

## Regression checks

```sh
node --test probes/typescript/runtime-probe.test.mjs
CANONICAL_PROBE_SELF_TEST=1 node probes/typescript/runtime-probe.mjs
```

Tests use only synthetic local modules. They cover nested names, aliases, descriptor accessors/errors, cycles, traversal limits, strict numeric parsing, path-hash collisions, console and native fd output, hung imports, oversized output, forged result data, authorization and redacted errors. No customer system is contacted.
