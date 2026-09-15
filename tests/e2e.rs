//! End-to-end conformance for example inputs, integrity, scope, and report safety.

use std::error::Error;
use std::str::FromStr;

use canonical_company_auditor::AuditError;
use canonical_company_auditor::engine::{assess, verify_report};
use canonical_company_auditor::model::{
    AssessmentRequest, CompanyManifest, EvidenceBundle, FindingStatus,
};
use canonical_company_auditor::program::built_in_program;
use canonical_company_auditor::report::{PromptKind, render_markdown, render_prompt};

fn request() -> Result<AssessmentRequest, serde_json::Error> {
    Ok(AssessmentRequest {
        manifest: serde_json::from_str::<CompanyManifest>(include_str!(
            "../examples/company.json"
        ))?,
        evidence: serde_json::from_str::<EvidenceBundle>(include_str!(
            "../examples/evidence.json"
        ))?,
    })
}

#[test]
fn example_assessment_is_deterministic_and_complete() -> Result<(), Box<dyn Error>> {
    let program = built_in_program()?;
    let first = assess(&request()?, &program)?;
    let second = assess(&request()?, &program)?;
    assert_eq!(first, second);
    assert_eq!(first.summary.passed, 9);
    assert_eq!(first.summary.failed, 9);
    assert_eq!(first.summary.unknown, 17);
    assert_eq!(first.summary.high_or_critical, 9);
    assert_eq!(first.findings.len(), 35);
    verify_report(&first)?;
    Ok(())
}

#[test]
fn missing_evidence_is_unknown_not_failed() -> Result<(), Box<dyn Error>> {
    let report = assess(&request()?, &built_in_program()?)?;
    let privacy = report
        .findings
        .iter()
        .find(|finding| finding.rule_id == "privacy.rights-workflow")
        .ok_or("missing privacy rule")?;
    assert_eq!(privacy.status, FindingStatus::Unknown);
    assert!(privacy.evidence_ids.is_empty());
    Ok(())
}

#[test]
fn markdown_never_contains_raw_fact_keys_or_values() -> Result<(), Box<dyn Error>> {
    let report = assess(&request()?, &built_in_program()?)?;
    let markdown = render_markdown(&report);
    assert!(markdown.contains("# Whole-company readiness assessment"));
    assert!(!markdown.contains("approved_and_current"));
    assert!(!markdown.contains("critical_overdue_count"));
    assert!(!markdown.contains("coverage_percent"));
    Ok(())
}

#[test]
fn tampered_report_is_rejected_before_prompting() -> Result<(), Box<dyn Error>> {
    let mut report = assess(&request()?, &built_in_program()?)?;
    report.findings[0].summary = "tampered".to_owned();
    assert!(matches!(verify_report(&report), Err(AuditError::Integrity)));
    Ok(())
}

#[test]
fn prompt_marks_every_json_line_as_untrusted_data() -> Result<(), Box<dyn Error>> {
    let report = assess(&request()?, &built_in_program()?)?;
    let prompt = render_prompt(PromptKind::from_str("gap-analysis")?, &report)?;
    assert!(prompt.contains("BEGIN UNTRUSTED ASSESSMENT DATA"));
    assert!(prompt.contains("DATA {"));
    assert!(prompt.contains("END UNTRUSTED ASSESSMENT DATA"));
    Ok(())
}

#[test]
fn cross_tenant_and_lookalike_scopes_fail_closed() -> Result<(), Box<dyn Error>> {
    let program = built_in_program()?;
    let mut cross_tenant = request()?;
    cross_tenant.evidence.tenant_id = "tenant-other".to_owned();
    assert!(matches!(
        assess(&cross_tenant, &program),
        Err(AuditError::ScopeDenied)
    ));

    let mut lookalike = request()?;
    lookalike.evidence.observations[0].subject = "organization/example-attacker".to_owned();
    assert!(matches!(
        assess(&lookalike, &program),
        Err(AuditError::ScopeDenied)
    ));
    Ok(())
}

#[test]
fn iso_profile_tracks_published_2024_amendment() -> Result<(), Box<dyn Error>> {
    let program: serde_json::Value =
        serde_json::from_str(include_str!("../programs/baseline-v1.json"))?;
    let frameworks = program["frameworks"]
        .as_array()
        .ok_or("frameworks must be an array")?;
    let iso = frameworks
        .iter()
        .find(|framework| framework["id"].as_str() == Some("iso-iec-27001-2022"))
        .ok_or("ISO/IEC 27001 profile missing")?;

    assert_eq!(iso["version"].as_str(), Some("2022 + Amd 1:2024"));
    assert_eq!(
        iso["sourceUrl"].as_str(),
        Some("https://www.iso.org/standard/27001")
    );
    assert!(
        iso["statusNote"]
            .as_str()
            .is_some_and(|note| note.contains("ISO/IEC 27001:2022/Amd 1:2024"))
    );
    Ok(())
}
