import "@typespec/json-schema";
using TypeSpec.JsonSchema;

namespace CanonicalReadiness;

@id("Identifier")
@pattern("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
scalar Identifier extends string;

@id("DateString")
@format("date")
@pattern("^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
scalar DateString extends string;

@id("FrameworkId")
enum FrameworkId {
  soc2: "soc2",
  nistCsf2: "nist-csf2",
  iso27001: "iso27001",
  gdpr: "gdpr",
  hipaa: "hipaa",
  pciDss: "pci-dss",
  cisControls: "cis-controls",
  csaCcm: "csa-ccm",
  iso27701: "iso27701",
  iso42001: "iso42001",
  nist80053: "nist-80053",
  nist800171: "nist-800171",
  nis2: "nis2",
  dora: "dora",
  fedrampRev5: "fedramp-rev5",
}

@id("ReadinessStatus")
enum ReadinessStatus {
  unanswered: "unanswered",
  implemented: "implemented",
  partial: "partial",
  missing: "missing",
  notApplicable: "not_applicable",
}

@id("ReadinessContext")
model ReadinessContext {
  customerId: Identifier;
  assessmentId: Identifier;

  @minLength(1)
  @maxLength(1000)
  @pattern("^[^\\u0000-\\u0008\\u000B\\u000C\\u000E-\\u001F\\u007F]*$")
  scope: string;

  periodStart: DateString;
  periodEnd: DateString;
  asOf: DateString;
}

@id("ReadinessAnswer")
model ReadinessAnswer {
  @pattern("^[a-z0-9-]+\\.q[0-9]{2}$")
  questionId: string;

  status: ReadinessStatus;

  @maxLength(128)
  @pattern("^[^\\u0000-\\u0008\\u000B\\u000C\\u000E-\\u001F\\u007F]*$")
  owner: string;

  @maxLength(4000)
  @pattern("^[^\\u0000-\\u0008\\u000B\\u000C\\u000E-\\u001F\\u007F]*$")
  notes: string;

  evidenceRef: "" | Identifier;
  evidenceDate: "" | DateString;

  @maxLength(128)
  @pattern("^[^\\u0000-\\u0008\\u000B\\u000C\\u000E-\\u001F\\u007F]*$")
  reviewer: string;

  dueDate: "" | DateString;
}

@id("ReadinessResponse")
model ReadinessResponse {
  schemaVersion: "canonical.readiness-response/v1";
  catalogVersion: "2026-09-07.1";
  frameworkId: FrameworkId;
  context: ReadinessContext;

  @maxItems(256)
  answers: ReadinessAnswer[];
}
