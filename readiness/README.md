# Independent customer readiness workbooks

Catalog revision **2026-09-07.1**, source review **September 7, 2026**. These are original Canonical Cloud pre-audit intake questions, not reproduced normative control text. Each of the 15 questionnaires contains ten broad, evidence-oriented questions. They are a starting point for a scoped pre-audit, **not an exhaustive clause/control assessment**. Obtain licensed standards and engage appropriately qualified assessors for the full engagement.

## Frameworks: complete each independently

| CLI/page identifier | Framework and pinned edition |
| --- | --- |
| `soc2` | SOC 2, 2017 Trust Services Criteria with revised points of focus 2022 |
| `nist-csf2` | NIST CSF 2.0 |
| `iso27001` | ISO/IEC 27001:2022, Amendment 1:2024 |
| `gdpr` | EU GDPR, Regulation 2016/679 |
| `hipaa` | Applicable 45 CFR Parts 160 and 164; proposed amendments are not presumed effective |
| `pci-dss` | PCI DSS 4.0.1 |
| `cis-controls` | CIS Controls v8.1 |
| `csa-ccm` | CSA CCM / CAIQ v4.1 |
| `iso27701` | ISO/IEC 27701:2025 |
| `iso42001` | ISO/IEC 42001:2023 |
| `nist-80053` | NIST SP 800-53 Rev. 5; assessment planning with 800-53A Rev. 5 |
| `nist-800171` | NIST SP 800-171 Rev. 3 and 800-171A Rev. 3 |
| `nis2` | NIS2 Directive 2022/2555 plus applicable national implementation |
| `dora` | DORA Regulation 2022/2554 and applicable technical standards |
| `fedramp-rev5` | FedRAMP Rev5 agency-authorization path, subject to current program eligibility |

`catalog.json` records each framework's scope caution, original questions, suggested evidence, review method, and official sources. A date-pinned catalog is not a promise that regulations never change. Recheck applicability, contractual edition, transition rules and authority sources at engagement opening; issue a new catalog revision for content changes. Do not silently migrate old answers to new questions.

## Rust CLI

First create a context file using `context.example.json` as the structural example, replacing its synthetic customer, assessment, scope, evidence-period and as-of values. The period represents evidence already available, not a future audit appointment.

```sh
cargo build --locked --bin canonical-auditor

# Create one blank, independently scoped response packet.
./target/debug/canonical-auditor readiness \
  --framework soc2 --context readiness/context.example.json \
  --format json --output soc2-answers.json

# Create a human-fillable Markdown checklist instead.
./target/debug/canonical-auditor readiness \
  --framework iso27001 --context readiness/context.example.json \
  --format markdown --output iso27001-checklist.md

# Assess a filled JSON packet, without fetching any evidence or probing a system.
./target/debug/canonical-auditor readiness \
  --framework soc2 --context readiness/context.example.json \
  --responses soc2-answers.json --format json --output soc2-preaudit.json

# Render the filled answers and gaps as Markdown.
./target/debug/canonical-auditor readiness \
  --framework soc2 --context readiness/context.example.json \
  --responses soc2-answers.json --format markdown --output soc2-preaudit.md
```

The command participates in the existing `.cli-flags.toml` / flags-2-env contract; corresponding `CANONICAL_AUDITOR_READINESS_*` environment bindings are declared there. No credential flags are introduced. Input files are limited to 1 MiB each. All outputs are create-new; an existing output is refused. `--output -` writes to stdout. Do not put customer answers in a source repository or CI logs.

Without `--responses`, JSON output is an editable **response**, and exit 0 means template export succeeded. With `--responses`, JSON output is a **report**, not an importable response; exit 2 identifies declared gaps, unanswered questions, unknown evidence or incomplete metadata. Invalid input/I/O is an error. Exit 0 is never certification: the report always contains `assurance: "none"`, and pending human review remains visible independently. Markdown can be filled by hand for a human engagement; automatic validation/import accepts only the JSON response contract.

## Customer web workflow

The web-server integration serves the chooser at `/app/readiness` and separate pages at `/app/readiness/<identifier>`. Start with the explicit context, answer the ten questions, and use Export JSON draft, Export Markdown or Print checklist. Import requires a JSON response for exactly the same customer, assessment, framework, catalog revision, scope and dates. The browser can use a CLI-generated response and vice versa.

Answers live only in the current tab's memory: **no automatic server save, browser persistence or evidence upload**. Export before leaving; exported files are unencrypted and must be stored in an approved protected location. The customer identifier is a label, not authentication or tenant authorization. A future durable-draft API must derive ownership from authenticated identity and enforce server-side row-level authorization, retention and deletion; these forms do not introduce that API.

Use only opaque evidence identifiers such as `vault:artifact-123`, not URLs, signed links, passwords, PHI, personal records or raw evidence. Actual evidence remains in the customer's approved evidence repository. Each framework needs its own explicit answer, explanation, owner and reviewer decision even when an approved artifact is relevant to several engagements. Neither a probe nor a crosswalk marks another framework complete.

## Contract and semantics

`response.schema.json` defines structure, bounded fields and basic formats. Both Rust and JavaScript additionally enforce semantic constraints: known question membership, duplicate IDs, exact revision/context matching, Gregorian dates and period ordering. Missing answers remain unanswered and stay in the denominator. Unknown fields, duplicate JSON object keys, malformed UTF-8, invalid scalar strings, oversized input and non-opaque evidence references are rejected at the relevant parsing/validation boundary.

Declarations are `unanswered`, `implemented`, `partial`, `missing`, or `not_applicable`. A declaration of implementation without an evidence reference/date is **unknown evidence**, not a proven failure. Partial/missing declarations remain gaps; missing owners, explanations and remediation dates are separately visible. N/A needs a reason, owner and recorded reviewer, but that name is self-reported, not a verified approval or signature. An evidence date and reference do not establish authenticity, freshness for the specific control, or operating effectiveness.

The shared fixtures test identical report semantics between Rust and JavaScript. Counts describe intake completeness only: there is no blended compliance score, no automatic cross-framework completion, and no assurance opinion.

## Tests

```sh
node --test readiness/readiness.test.mjs
cargo test --locked --all-targets
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
```

Review `methodology.md` before conducting an engagement. The separate runtime-probe instructions are in `../docs/runtime-probe-safety.md`. No live probes are triggered by exporting or filling a workbook.
