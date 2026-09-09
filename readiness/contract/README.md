# Readiness wire-contract peer authorities

The readiness response has two independently authored authorities at the same level:

1. `main.tsp` — TypeSpec source; and
2. `../response.schema.json` — JSON Schema Draft 2020-12 source.

Neither file is generated from the other. `ORESoftware/typespec-json-schema-validator` (TJSV) generates a comparison-only JSON Schema witness from TypeSpec, compares both declaration structure and runtime behavior, and stops evaluation when the authorities diverge. The generated witness, parity receipt, Contract IR and consumer-verification receipt are evidence only; they never overwrite either authority.

CI pins TJSV to an immutable reviewed commit and performs three gates:

- peer-authority `check`, including the independently maintained valid/invalid instance corpus;
- `verify-contract-ir`, requiring the exact current TypeSpec, authored schema, generated witness, parity receipt and complete declaration inventory; and
- `test-consumer-admission`, which proves altered evidence and incomplete declaration scopes are rejected.

This contract is the portable wire shape shared by the Rust CLI/service and JavaScript browser implementation. Existing Rust/JavaScript golden fixtures continue to test runtime report semantics. Semantic rules that depend on an engagement context — exact selected-framework question membership, unique question IDs, Gregorian date validity/order, exact customer/assessment/scope matching, evidence freshness and reviewer authorization — remain runtime admission rules and are deliberately not misrepresented as JSON-shape constraints.

Framework readiness answers remain independent. A contract match does not copy an answer, N/A decision, evidence conclusion or approval from one framework to another.

## Instance corpus

`instances/ReadinessResponse/valid/` contains wire packets both authorities must accept. `invalid/` contains packets both authorities must reject. Add regression fixtures when a new cross-runtime boundary bug is found. Never place real customer data, credentials, PHI or evidence contents in this repository.
