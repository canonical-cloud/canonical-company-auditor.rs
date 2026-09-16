# Customer audit repository and publishing boundary

Canonical Cloud uses one private Git repository per customer/audit engagement as the durable source of truth for audit inputs, evidence indexes, workpapers, generated reports, and customer-visible artifacts.

This design is a readiness/evidence workflow. It does not turn generated output into an independent attestation, certification, legal conclusion, or auditor opinion.

## Repository contract

```text
.
├── .canonical-cfg.toml       # scope, providers, account IDs, secret references
├── env/
│   └── enc/                  # SOPS + age encrypted material only
├── evidence/                 # normalized/private evidence and collection manifests
├── workpapers/               # private audit workpapers and reviewer notes
├── reports/                  # complete generated reports/packages
├── manifests/                # hashes, provenance, source/program versions
├── customer/                 # the ONLY path eligible for publication
│   ├── index.html
│   ├── reports/
│   └── manifest.json
└── .github/workflows/
    └── publish-customer.yml
```

The repository MUST be private unless an explicit customer contract says otherwise. `customer/` is a disclosure boundary, not a convenience copy of the repository.

## `.canonical-cfg.toml`

The configuration file is the machine-readable inventory of audit scope and service connections. It may contain non-secret identifiers such as cloud account IDs, project IDs, organization names, regions, API base URLs, collection allowlists, and report/publishing settings.

It MUST NOT contain plaintext API tokens, passwords, private keys, service-role keys, database passwords, session cookies, or other bearer credentials. Credentials are represented by references such as:

```toml
auth_ref = "env:CLOUDFLARE_API_TOKEN"
secret_file = "sops:env/enc/customer.enc.yaml"
```

Collectors resolve those references at runtime. The configuration validator should fail closed on values that look like inline credentials when `allow_plaintext_secrets = false`.

Every provider used for evidence collection is read-only by default. A connector that cannot operate with a read-only scope must be disabled or isolated until its required permissions have been reviewed.

## Interactive and non-interactive collection

Automation uses `--non-interactive`: all required fields must already be present in `.canonical-cfg.toml`, environment references, or explicitly supplied input files. Missing fields are returned as structured errors; automation must never guess tenant/account identifiers or silently select a different account.

`--interactive` may ask an operator to supply missing non-secret metadata or choose among discovered read-only scopes. Secret answers should be written only to the approved secret store/SOPS+age path, never echoed into reports, logs, shell history, or the TOML file as plaintext.

## Publication architecture

The recommended production path is:

```text
private customer Git repository
          |
          | CI checks + allowlist + secret scan
          v
     customer/ only
          |
          | upload
          v
     Cloudflare R2
          |
          | custom domain
          v
Cloudflare Access / signed-link policy
          |
          v
       customer
```

Do not use the Git repository itself as a CDN origin. Publishing only a generated/curated subtree prevents repository metadata, workpapers, raw evidence, encrypted secret material, configuration, and historical commits from becoming customer-facing by accident.

For internal or named customer users, prefer a Cloudflare custom domain protected by Access. For external recipients who should not be enrolled in the identity provider, use short-lived signed/presigned links through a narrowly scoped delivery service. `r2.dev` is development-only and must be disabled for production customer artifacts.

## Publish gate

A publication job MUST fail unless all of these conditions hold:

1. source path resolves beneath `customer/` after symlink and canonical-path resolution;
2. no symlink, hard-link trick, archive member, or path traversal can escape that root;
3. a secret scanner finds no high-confidence credential material;
4. every published object appears in an allowlist generated from the customer manifest;
5. each object has an expected MIME type and disclosure classification;
6. a SHA-256 integrity manifest is generated before upload;
7. the manifest records the Git commit SHA and assessment/program versions;
8. upload credentials can write only the customer's R2 bucket/prefix;
9. no delete/bucket-administration permission is granted to the normal publisher;
10. post-publish negative tests verify private paths are unreachable.

## Required negative tests

The customer endpoint must return an authorization failure or not-found response for attempts to access any of the following:

```text
/.git/config
/.canonical-cfg.toml
/env/
/env/enc/
/evidence/
/workpapers/
/reports/                 # unless explicitly copied into customer/reports/
/manifests/               # unless a curated public manifest is copied into customer/
../evidence/
%2e%2e/evidence/
customer/../evidence/
```

Tests should also exercise encoded separators, duplicate slashes, Unicode normalization edge cases, symlink targets, and archive extraction paths.

## Integrity and provenance

Each customer publication should produce a machine-readable manifest similar to:

```json
{
  "schemaVersion": "canonical.customer-publication/v1",
  "customerId": "customer-1-demo",
  "sourceCommit": "<40-hex commit>",
  "assessmentProgram": "<id/version>",
  "objects": [
    {
      "path": "reports/readiness.html",
      "bytes": 12345,
      "sha256": "<64-hex digest>",
      "contentType": "text/html"
    }
  ]
}
```

Generated evidence and reports should be append-oriented/content-addressed where practical. Corrections produce a new artifact and manifest entry rather than silently changing historical evidence.

## Customer repository lifecycle

1. create the private repository from the approved customer-audit template;
2. commit a synthetic/scope-only `.canonical-cfg.toml` with secret references;
3. provision read-only credentials outside Git and bind them to the smallest feasible account/project scope;
4. run collection and readiness checks;
5. review `fail` and `unknown` findings with a human control owner;
6. generate complete internal reports under `reports/`;
7. curate customer-facing material into `customer/`;
8. run publication gates and upload only `customer/`;
9. preserve the publication manifest and CI evidence in Git;
10. revoke temporary credentials and record closure/retention status when the engagement ends.

## Compliance relevance

This repository contract supports evidence collection and change/disclosure controls that are useful across SOC 2 Trust Services Criteria, NIST CSF 2.0 / SP 800-53, and ISO/IEC 27001. Framework mappings remain directional audit aids: a passing technical check does not by itself demonstrate that an entire framework requirement is satisfied, and cross-framework similarity does not make the frameworks equivalent.
