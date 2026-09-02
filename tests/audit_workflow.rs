//! End-to-end dress-rehearsal, full-audit, custody, review, and package tests.

use std::collections::BTreeMap;
use std::error::Error;

use canonical_company_auditor::AuditError;
use canonical_company_auditor::audit::{
    AuditConclusion, ControlTestStatus, run_audit, verify_dossier,
};
use canonical_company_auditor::engagement::{
    ActorRole, AuditEngagement, AuditMilestone, EngagementActor, EngagementEvent, EngagementMode,
    EngagementPhase, EvidenceRequest, RequestStatus, ReviewConclusion, ReviewSignoff, SamplePlan,
    SamplingMethod, Workpaper, WorkpaperConclusion,
};
use canonical_company_auditor::evidence::digest;
use canonical_company_auditor::model::{
    AssessmentRequest, CompanyManifest, EVIDENCE_SCHEMA, EvidenceBundle, EvidenceObservation,
    EvidenceSource,
};
use canonical_company_auditor::package::{build_audit_package, verify_audit_package};
use canonical_company_auditor::program::{AssessmentProgram, built_in_program};

fn passing_request(program: &AssessmentProgram) -> Result<AssessmentRequest, Box<dyn Error>> {
    let manifest =
        serde_json::from_str::<CompanyManifest>(include_str!("../examples/company.json"))?;
    let observations = program
        .rules
        .iter()
        .enumerate()
        .map(|(index, rule)| EvidenceObservation {
            external_id: format!("full-audit-evidence-{index}"),
            evidence_type: rule.evidence_type.clone(),
            subject: manifest.scope_id.clone(),
            source: EvidenceSource::Manual {
                submitted_by: "evidence-owner".to_owned(),
            },
            collected_at: manifest.assessment_period.ends_at,
            valid_until: manifest.assessment_period.ends_at + 86_400,
            facts: BTreeMap::from([(rule.condition.fact.clone(), rule.condition.expected.clone())]),
            attestation: Some(
                "Reviewed source artifact retained in the audit data room.".to_owned(),
            ),
        })
        .collect();
    Ok(AssessmentRequest {
        evidence: EvidenceBundle {
            schema_version: EVIDENCE_SCHEMA.to_owned(),
            tenant_id: manifest.tenant_id.clone(),
            scope_id: manifest.scope_id.clone(),
            observations,
        },
        manifest,
    })
}

fn actors() -> Vec<EngagementActor> {
    vec![
        EngagementActor {
            actor_id: "audit-lead".to_owned(),
            role: ActorRole::AuditLead,
            organization: "Independent Audit Example".to_owned(),
            display_name: "Audit Lead".to_owned(),
            independent: true,
        },
        EngagementActor {
            actor_id: "auditor-one".to_owned(),
            role: ActorRole::Auditor,
            organization: "Independent Audit Example".to_owned(),
            display_name: "Auditor One".to_owned(),
            independent: true,
        },
        EngagementActor {
            actor_id: "reviewer-one".to_owned(),
            role: ActorRole::Reviewer,
            organization: "Independent Audit Example".to_owned(),
            display_name: "Reviewer One".to_owned(),
            independent: true,
        },
        EngagementActor {
            actor_id: "evidence-owner".to_owned(),
            role: ActorRole::EvidenceOwner,
            organization: "Example Company".to_owned(),
            display_name: "Evidence Owner".to_owned(),
            independent: false,
        },
    ]
}

fn finalized_engagement(
    request: &AssessmentRequest,
    program: &AssessmentProgram,
) -> Result<AuditEngagement, AuditError> {
    let evidence_requests = program
        .rules
        .iter()
        .enumerate()
        .map(|(index, rule)| EvidenceRequest {
            request_id: format!("request-{index}"),
            title: format!("Provide evidence for {}", rule.title),
            rule_ids: vec![rule.id.clone()],
            owner_id: "evidence-owner".to_owned(),
            due_at: request.manifest.assessment_period.ends_at,
            status: RequestStatus::Accepted,
            evidence_external_ids: vec![format!("full-audit-evidence-{index}")],
            auditor_note: "Evidence accepted after completeness and relevance review.".to_owned(),
        })
        .collect::<Vec<_>>();
    let first_fingerprint = digest(&"population-member-0")?;
    let sample_plans = vec![SamplePlan {
        sample_plan_id: "sample-plan-0".to_owned(),
        rule_id: program.rules[0].id.clone(),
        population_id: "population-access-reviews".to_owned(),
        population_size: 1,
        method: SamplingMethod::FullPopulation,
        sample_size: 1,
        selected_item_fingerprints: vec![first_fingerprint],
        rationale: "The complete one-item illustrative population was tested.".to_owned(),
    }];
    let workpapers = program
        .rules
        .iter()
        .enumerate()
        .map(|(index, rule)| Workpaper {
            workpaper_id: format!("workpaper-{index}"),
            rule_id: rule.id.clone(),
            preparer_id: "auditor-one".to_owned(),
            prepared_at: request.manifest.assessment_period.ends_at,
            procedure_performed: format!(
                "Inspected the indexed evidence and re-performed the deterministic test for {}.",
                rule.title
            ),
            design_conclusion: WorkpaperConclusion::Effective,
            operating_conclusion: WorkpaperConclusion::Effective,
            evidence_external_ids: vec![format!("full-audit-evidence-{index}")],
            sample_plan_id: (index == 0).then(|| "sample-plan-0".to_owned()),
            exceptions: Vec::new(),
            reviewer_signoff: Some(ReviewSignoff {
                reviewer_id: "reviewer-one".to_owned(),
                reviewed_at: request.manifest.assessment_period.ends_at + 1,
                conclusion: ReviewConclusion::Approved,
                note: "Procedure, evidence references, and conclusion reviewed.".to_owned(),
            }),
        })
        .collect();
    Ok(AuditEngagement {
        schema_version: "canonical.audit-engagement/v1".to_owned(),
        engagement_id: "engagement-full-example".to_owned(),
        tenant_id: request.manifest.tenant_id.clone(),
        scope_id: request.manifest.scope_id.clone(),
        title: "Illustrative multi-framework full audit".to_owned(),
        mode: EngagementMode::FullAudit,
        phase: EngagementPhase::Finalized,
        period: request.manifest.assessment_period.clone(),
        framework_ids: request.manifest.frameworks.clone(),
        objective: "Evaluate control design and operation across the declared company scope."
            .to_owned(),
        criteria: "Canonical-authored tests mapped to selected public framework references."
            .to_owned(),
        actors: actors(),
        milestones: vec![AuditMilestone {
            milestone_id: "fieldwork-complete".to_owned(),
            title: "Fieldwork complete".to_owned(),
            due_at: request.manifest.assessment_period.ends_at,
            completed_at: Some(request.manifest.assessment_period.ends_at),
        }],
        evidence_requests,
        sample_plans,
        workpapers,
        management_responses: Vec::new(),
        events: vec![EngagementEvent {
            sequence: 0,
            event_type: "engagement.finalized".to_owned(),
            actor_id: "audit-lead".to_owned(),
            occurred_at: request.manifest.assessment_period.ends_at + 2,
            subject_id: "engagement-full-example".to_owned(),
            payload_sha256: digest(&"finalized illustrative engagement")?,
        }],
        report_recipients: vec!["Board Audit Committee".to_owned()],
    })
}

#[test]
fn finalized_full_audit_has_complete_review_and_package() -> Result<(), Box<dyn Error>> {
    let program = built_in_program()?;
    let request = passing_request(&program)?;
    let engagement = finalized_engagement(&request, &program)?;
    let dossier = run_audit(&request, &engagement, &program)?;

    assert_eq!(dossier.conclusion, AuditConclusion::Satisfactory);
    assert_eq!(dossier.summary.total_controls, program.rules.len());
    assert_eq!(dossier.summary.satisfactory_controls, program.rules.len());
    assert_eq!(dossier.summary.evidence_coverage_basis_points, 10_000);
    assert_eq!(dossier.summary.review_coverage_basis_points, 10_000);
    assert!(
        dossier
            .control_results
            .iter()
            .all(|item| item.audit_status == ControlTestStatus::Satisfactory)
    );
    verify_dossier(&dossier)?;

    let package = build_audit_package(&dossier)?;
    assert_eq!(package.documents.len(), 10);
    assert!(
        package
            .documents
            .iter()
            .any(|item| item.file_name == "08-framework-crosswalk.md")
    );
    verify_audit_package(&package)?;
    Ok(())
}

#[test]
fn package_excludes_normalized_fact_names_and_values() -> Result<(), Box<dyn Error>> {
    let program = built_in_program()?;
    let request = passing_request(&program)?;
    let dossier = run_audit(
        &request,
        &finalized_engagement(&request, &program)?,
        &program,
    )?;
    let serialized = serde_json::to_string(&build_audit_package(&dossier)?)?;
    assert!(!serialized.contains("approved_and_current"));
    assert!(!serialized.contains("critical_overdue_count"));
    Ok(())
}

#[test]
fn tampered_package_document_is_rejected() -> Result<(), Box<dyn Error>> {
    let program = built_in_program()?;
    let request = passing_request(&program)?;
    let dossier = run_audit(
        &request,
        &finalized_engagement(&request, &program)?,
        &program,
    )?;
    let mut package = build_audit_package(&dossier)?;
    package.documents[0].content.push_str("tampered");
    assert!(matches!(
        verify_audit_package(&package),
        Err(AuditError::Integrity)
    ));
    Ok(())
}

#[test]
fn finalized_audit_requires_every_workpaper() -> Result<(), Box<dyn Error>> {
    let program = built_in_program()?;
    let request = passing_request(&program)?;
    let mut engagement = finalized_engagement(&request, &program)?;
    engagement.workpapers.pop();
    assert!(run_audit(&request, &engagement, &program).is_err());
    Ok(())
}

#[test]
fn reviewer_cannot_approve_their_own_work() -> Result<(), Box<dyn Error>> {
    let program = built_in_program()?;
    let request = passing_request(&program)?;
    let mut engagement = finalized_engagement(&request, &program)?;
    if let Some(signoff) = &mut engagement.workpapers[0].reviewer_signoff {
        signoff.reviewer_id = "auditor-one".to_owned();
    }
    assert!(run_audit(&request, &engagement, &program).is_err());
    Ok(())
}
