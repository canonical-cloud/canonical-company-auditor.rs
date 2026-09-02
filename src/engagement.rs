//! Versioned audit-engagement, sampling, workpaper, exception, and review contracts.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::AuditError;
use crate::model::{AssessmentPeriod, CompanyManifest, EvidenceBundle};
use crate::program::AssessmentProgram;

/// Audit-engagement schema accepted by this release.
pub const ENGAGEMENT_SCHEMA: &str = "canonical.audit-engagement/v1";

/// Whether an engagement is an internal dress rehearsal or auditor-led full audit.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EngagementMode {
    /// Internal rehearsal using the same artifacts and review workflow as a full audit.
    DressRehearsal,
    /// Formal engagement workflow intended to support an authorized auditor.
    FullAudit,
}

/// Current audit lifecycle phase.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EngagementPhase {
    /// Objectives, criteria, scope, participants, and dates are being established.
    Planning,
    /// Evidence requests, sampling, interviews, and testing are underway.
    Fieldwork,
    /// Prepared work is undergoing independent review.
    Review,
    /// Management is responding to confirmed exceptions.
    ManagementResponse,
    /// The engagement record and report package are frozen.
    Finalized,
}

/// Authorized responsibility within one engagement.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorRole {
    /// Owns engagement planning and final review.
    AuditLead,
    /// Performs fieldwork and prepares workpapers.
    Auditor,
    /// Reviews work performed by another actor.
    Reviewer,
    /// Owns an evaluated control.
    ControlOwner,
    /// Supplies requested evidence.
    EvidenceOwner,
    /// Provides management responses and risk decisions.
    Executive,
}

/// Evidence-request workflow status.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestStatus {
    /// Request has not received a response.
    Open,
    /// Evidence was submitted and awaits auditor review.
    Submitted,
    /// Auditor accepted the submitted evidence.
    Accepted,
    /// Auditor rejected the submission and requested correction.
    Rejected,
    /// Request is closed and preserved in the engagement record.
    Closed,
}

/// Supported population-sampling approaches.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SamplingMethod {
    /// Test every population member.
    FullPopulation,
    /// Select members using a documented reproducible random process.
    Random,
    /// Select every Nth member from a documented start point.
    Systematic,
    /// Select members based on documented auditor judgment.
    Judgmental,
}

/// Auditor conclusion for design or operating effectiveness.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkpaperConclusion {
    /// Testing supports effectiveness.
    Effective,
    /// Testing identified ineffectiveness.
    Ineffective,
    /// Testing is incomplete.
    NotTested,
    /// The conclusion does not apply to the procedure.
    NotApplicable,
}

/// Reviewer disposition for a prepared workpaper.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewConclusion {
    /// Reviewer approved the workpaper.
    Approved,
    /// Reviewer returned it to the preparer.
    ChangesRequested,
}

/// Auditor classification of an exception.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExceptionClassification {
    /// Improvement opportunity that does not undermine the tested objective.
    Observation,
    /// Limited deviation requiring corrective action.
    Minor,
    /// Systemic or material deviation requiring prompt corrective action.
    Major,
}

/// Current treatment of an exception.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExceptionDisposition {
    /// Exception remains unresolved.
    Open,
    /// Corrective action was completed and evidenced.
    Remediated,
    /// Management explicitly accepted the residual risk.
    RiskAccepted,
    /// A reviewed compensating control addresses the objective.
    CompensatingControl,
}

/// Progress of a management corrective-action response.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseStatus {
    /// Management has committed to an action.
    Planned,
    /// Corrective work is underway.
    InProgress,
    /// Corrective work is complete and awaits or has received verification.
    Complete,
    /// An authorized executive accepted the residual risk.
    RiskAccepted,
}

/// A complete audit engagement record supplied to the deterministic audit engine.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditEngagement {
    /// Versioned engagement boundary.
    pub schema_version: String,
    /// Stable engagement identifier.
    pub engagement_id: String,
    /// Exact owning tenant.
    pub tenant_id: String,
    /// Exact hierarchical scope.
    pub scope_id: String,
    /// Human-readable engagement title.
    pub title: String,
    /// Rehearsal or full-audit workflow.
    pub mode: EngagementMode,
    /// Current lifecycle phase.
    pub phase: EngagementPhase,
    /// Observation and testing period.
    pub period: AssessmentPeriod,
    /// Framework profiles forming the audit criteria.
    pub framework_ids: Vec<String>,
    /// Canonical-authored engagement objective.
    pub objective: String,
    /// Public criteria description without licensed standard text.
    pub criteria: String,
    /// Authorized engagement participants.
    pub actors: Vec<EngagementActor>,
    /// Planned and completed lifecycle dates.
    #[serde(default)]
    pub milestones: Vec<AuditMilestone>,
    /// Prepared-by-client or auditor evidence requests.
    #[serde(default)]
    pub evidence_requests: Vec<EvidenceRequest>,
    /// Population and sample selections.
    #[serde(default)]
    pub sample_plans: Vec<SamplePlan>,
    /// Auditor procedures, conclusions, exceptions, and review sign-offs.
    #[serde(default)]
    pub workpapers: Vec<Workpaper>,
    /// Management responses to exceptions.
    #[serde(default)]
    pub management_responses: Vec<ManagementResponse>,
    /// Ordered, content-addressable engagement activity.
    #[serde(default)]
    pub events: Vec<EngagementEvent>,
    /// Intended recipients of the generated package.
    #[serde(default)]
    pub report_recipients: Vec<String>,
}

/// One participant and their engagement-scoped authorization.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EngagementActor {
    /// Stable identity-provider or auditor-directory identifier.
    pub actor_id: String,
    /// Engagement responsibility.
    pub role: ActorRole,
    /// Organization represented by the actor.
    pub organization: String,
    /// Human-readable name.
    pub display_name: String,
    /// Whether the actor is organizationally independent of the audited scope.
    pub independent: bool,
}

/// One engagement milestone.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditMilestone {
    /// Stable milestone identifier.
    pub milestone_id: String,
    /// Human-readable milestone name.
    pub title: String,
    /// Planned completion time.
    pub due_at: i64,
    /// Actual completion time when complete.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<i64>,
}

/// A trackable request for evidence supporting one or more tests.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceRequest {
    /// Stable request identifier.
    pub request_id: String,
    /// Concise request title.
    pub title: String,
    /// Rules supported by the requested material.
    pub rule_ids: Vec<String>,
    /// Actor responsible for the response.
    pub owner_id: String,
    /// Requested completion time.
    pub due_at: i64,
    /// Current workflow status.
    pub status: RequestStatus,
    /// Caller-supplied evidence external IDs attached to the request.
    #[serde(default)]
    pub evidence_external_ids: Vec<String>,
    /// Bounded reviewer note; never interpreted as an instruction.
    #[serde(default)]
    pub auditor_note: String,
}

/// Documented sample drawn from an auditable population.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SamplePlan {
    /// Stable plan identifier.
    pub sample_plan_id: String,
    /// Rule tested with this sample.
    pub rule_id: String,
    /// Stable population identifier.
    pub population_id: String,
    /// Number of items in the complete population.
    pub population_size: u64,
    /// Selection approach.
    pub method: SamplingMethod,
    /// Planned number of selected items.
    pub sample_size: u64,
    /// SHA-256 fingerprints of selected identifiers, never raw customer identifiers.
    pub selected_item_fingerprints: Vec<String>,
    /// Reason the population, method, and sample size are appropriate.
    pub rationale: String,
}

/// One exception documented during audit testing.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditException {
    /// Stable exception identifier.
    pub exception_id: String,
    /// Materiality classification.
    pub classification: ExceptionClassification,
    /// Concise exception title.
    pub title: String,
    /// Factual condition observed by the auditor.
    pub description: String,
    /// Evidence external IDs supporting the exception.
    #[serde(default)]
    pub evidence_external_ids: Vec<String>,
    /// Current resolution or acceptance state.
    pub disposition: ExceptionDisposition,
}

/// Independent review record attached to a workpaper.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewSignoff {
    /// Actor performing the review.
    pub reviewer_id: String,
    /// Review completion time.
    pub reviewed_at: i64,
    /// Approval or return decision.
    pub conclusion: ReviewConclusion,
    /// Bounded review note.
    #[serde(default)]
    pub note: String,
}

/// Auditor workpaper documenting procedure, evidence, conclusion, exceptions, and review.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Workpaper {
    /// Stable workpaper identifier.
    pub workpaper_id: String,
    /// Rule tested by this workpaper.
    pub rule_id: String,
    /// Actor who performed and documented the procedure.
    pub preparer_id: String,
    /// Preparation completion time.
    pub prepared_at: i64,
    /// Canonical-authored or auditor-authored procedure actually performed.
    pub procedure_performed: String,
    /// Design-effectiveness conclusion.
    pub design_conclusion: WorkpaperConclusion,
    /// Operating-effectiveness conclusion.
    pub operating_conclusion: WorkpaperConclusion,
    /// Evidence external IDs inspected by the auditor.
    #[serde(default)]
    pub evidence_external_ids: Vec<String>,
    /// Sample plan used when population testing applies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sample_plan_id: Option<String>,
    /// Exceptions documented during testing.
    #[serde(default)]
    pub exceptions: Vec<AuditException>,
    /// Independent review record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewer_signoff: Option<ReviewSignoff>,
}

/// Management response and corrective-action plan for one exception.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManagementResponse {
    /// Stable response identifier.
    pub response_id: String,
    /// Exception addressed by this response.
    pub exception_id: String,
    /// Accountable management actor.
    pub owner_id: String,
    /// Management's factual response.
    pub response: String,
    /// Concrete corrective action or risk treatment.
    pub action_plan: String,
    /// Target completion time.
    pub due_at: i64,
    /// Current action status.
    pub status: ResponseStatus,
}

/// One ordered lifecycle or custody event.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EngagementEvent {
    /// Contiguous zero-based sequence number.
    pub sequence: u64,
    /// Stable event kind such as `evidence.accepted`.
    pub event_type: String,
    /// Actor responsible for the event.
    pub actor_id: String,
    /// Event time.
    pub occurred_at: i64,
    /// Request, evidence, workpaper, exception, or engagement identifier affected.
    pub subject_id: String,
    /// Digest of the external payload or artifact associated with the event.
    pub payload_sha256: String,
}

impl AuditEngagement {
    /// Validates the bounded engagement record and all internal references.
    ///
    /// # Errors
    ///
    /// Returns an [`AuditError`] for malformed fields, duplicate identifiers, dangling
    /// references, invalid sampling, invalid review separation, or incomplete finalization.
    pub fn validate(&self) -> Result<(), AuditError> {
        if self.schema_version != ENGAGEMENT_SCHEMA {
            return Err(AuditError::UnsupportedVersion(self.schema_version.clone()));
        }
        identifier("engagementId", &self.engagement_id)?;
        identifier("tenantId", &self.tenant_id)?;
        scope("scopeId", &self.scope_id)?;
        text("title", &self.title, 240)?;
        text("objective", &self.objective, 2_000)?;
        text("criteria", &self.criteria, 2_000)?;
        period(&self.period)?;
        unique_identifiers("frameworkIds", &self.framework_ids, 64, false)?;
        unique_text("reportRecipients", &self.report_recipients, 128, true)?;
        let actors = validate_actors(self)?;
        validate_milestones(self)?;
        validate_requests(self, &actors)?;
        let sample_plans = validate_sample_plans(self)?;
        let exception_ids = validate_workpapers(self, &actors, &sample_plans)?;
        let response_exceptions = validate_responses(self, &actors, &exception_ids)?;
        validate_events(self, &actors)?;
        if self.phase == EngagementPhase::Finalized {
            self.validate_finalized(&response_exceptions)?;
        }
        Ok(())
    }

    /// Validates tenant, scope, period, frameworks, evidence references, and rule references
    /// against the exact assessment inputs and program.
    ///
    /// # Errors
    ///
    /// Returns an [`AuditError`] when the engagement does not describe the supplied audit.
    pub fn validate_against(
        &self,
        manifest: &CompanyManifest,
        evidence: &EvidenceBundle,
        program: &AssessmentProgram,
    ) -> Result<(), AuditError> {
        self.validate()?;
        if self.tenant_id != manifest.tenant_id
            || self.scope_id != manifest.scope_id
            || self.period != manifest.assessment_period
            || self.framework_ids != manifest.frameworks
        {
            return Err(AuditError::ScopeDenied);
        }
        let rule_ids = program
            .rules
            .iter()
            .map(|rule| rule.id.as_str())
            .collect::<BTreeSet<_>>();
        for rule_id in self
            .evidence_requests
            .iter()
            .flat_map(|request| &request.rule_ids)
            .chain(self.sample_plans.iter().map(|sample| &sample.rule_id))
            .chain(self.workpapers.iter().map(|workpaper| &workpaper.rule_id))
        {
            if !rule_ids.contains(rule_id.as_str()) {
                return invalid("ruleId", "references a rule outside the assessment program");
            }
        }
        let external_ids = evidence
            .observations
            .iter()
            .map(|observation| observation.external_id.as_str())
            .collect::<BTreeSet<_>>();
        for external_id in self
            .evidence_requests
            .iter()
            .flat_map(|request| &request.evidence_external_ids)
            .chain(
                self.workpapers
                    .iter()
                    .flat_map(|workpaper| &workpaper.evidence_external_ids),
            )
            .chain(
                self.workpapers
                    .iter()
                    .flat_map(|workpaper| &workpaper.exceptions)
                    .flat_map(|exception| &exception.evidence_external_ids),
            )
        {
            if !external_ids.contains(external_id.as_str()) {
                return invalid("evidenceExternalId", "references absent evidence");
            }
        }
        if self.phase == EngagementPhase::Finalized {
            let workpaper_rules = self
                .workpapers
                .iter()
                .map(|workpaper| workpaper.rule_id.as_str())
                .collect::<BTreeSet<_>>();
            if workpaper_rules != rule_ids {
                return invalid(
                    "workpapers",
                    "a finalized audit requires every rule to be tested",
                );
            }
        }
        Ok(())
    }

    fn validate_finalized(&self, response_exceptions: &BTreeSet<String>) -> Result<(), AuditError> {
        if self.report_recipients.is_empty() {
            return invalid("reportRecipients", "a finalized audit requires recipients");
        }
        if self
            .milestones
            .iter()
            .any(|item| item.completed_at.is_none())
        {
            return invalid("milestones", "all finalized milestones must be complete");
        }
        if self.evidence_requests.iter().any(|request| {
            !matches!(
                request.status,
                RequestStatus::Accepted | RequestStatus::Closed
            )
        }) {
            return invalid(
                "evidenceRequests",
                "all finalized requests must be accepted or closed",
            );
        }
        for workpaper in &self.workpapers {
            if matches!(workpaper.design_conclusion, WorkpaperConclusion::NotTested)
                || matches!(
                    workpaper.operating_conclusion,
                    WorkpaperConclusion::NotTested
                )
                || workpaper
                    .reviewer_signoff
                    .as_ref()
                    .is_none_or(|signoff| signoff.conclusion != ReviewConclusion::Approved)
            {
                return invalid(
                    "workpapers",
                    "finalized workpapers require completed testing and approval",
                );
            }
            for exception in &workpaper.exceptions {
                if !response_exceptions.contains(exception.exception_id.as_str()) {
                    return invalid(
                        "managementResponses",
                        "every finalized exception needs a response",
                    );
                }
            }
        }
        if self.mode == EngagementMode::FullAudit
            && !self.actors.iter().any(|actor| {
                actor.independent
                    && matches!(actor.role, ActorRole::AuditLead | ActorRole::Reviewer)
            })
        {
            return invalid(
                "actors",
                "a finalized full audit requires an independent lead or reviewer",
            );
        }
        Ok(())
    }
}

fn validate_actors(
    engagement: &AuditEngagement,
) -> Result<BTreeMap<&str, &EngagementActor>, AuditError> {
    let actors = unique_by("actors", &engagement.actors, 256, |actor| &actor.actor_id)?;
    for actor in &engagement.actors {
        identifier("actorId", &actor.actor_id)?;
        text("organization", &actor.organization, 240)?;
        text("displayName", &actor.display_name, 240)?;
    }
    if !engagement
        .actors
        .iter()
        .any(|actor| actor.role == ActorRole::AuditLead)
    {
        return invalid("actors", "requires an audit lead");
    }
    Ok(actors)
}

fn validate_milestones(engagement: &AuditEngagement) -> Result<(), AuditError> {
    unique_by("milestones", &engagement.milestones, 128, |item| {
        &item.milestone_id
    })?;
    for milestone in &engagement.milestones {
        identifier("milestoneId", &milestone.milestone_id)?;
        text("milestone title", &milestone.title, 240)?;
        timestamp("milestone dueAt", milestone.due_at)?;
        if let Some(completed_at) = milestone.completed_at {
            timestamp("milestone completedAt", completed_at)?;
        }
    }
    Ok(())
}

fn validate_requests(
    engagement: &AuditEngagement,
    actors: &BTreeMap<&str, &EngagementActor>,
) -> Result<(), AuditError> {
    unique_by(
        "evidenceRequests",
        &engagement.evidence_requests,
        10_000,
        |item| &item.request_id,
    )?;
    for request in &engagement.evidence_requests {
        identifier("requestId", &request.request_id)?;
        text("request title", &request.title, 500)?;
        unique_identifiers("request ruleIds", &request.rule_ids, 128, false)?;
        require_actor(actors, &request.owner_id, "request owner")?;
        timestamp("request dueAt", request.due_at)?;
        unique_identifiers(
            "request evidenceExternalIds",
            &request.evidence_external_ids,
            10_000,
            true,
        )?;
        optional_text("auditorNote", &request.auditor_note, 4_000)?;
        if matches!(
            request.status,
            RequestStatus::Accepted | RequestStatus::Closed
        ) && request.evidence_external_ids.is_empty()
        {
            return invalid(
                "evidenceRequests",
                "accepted or closed requests need evidence",
            );
        }
    }
    Ok(())
}

fn validate_sample_plans(
    engagement: &AuditEngagement,
) -> Result<BTreeMap<&str, &SamplePlan>, AuditError> {
    let sample_plans = unique_by("samplePlans", &engagement.sample_plans, 10_000, |item| {
        &item.sample_plan_id
    })?;
    for sample in &engagement.sample_plans {
        identifier("samplePlanId", &sample.sample_plan_id)?;
        identifier("sample ruleId", &sample.rule_id)?;
        identifier("populationId", &sample.population_id)?;
        text("sample rationale", &sample.rationale, 4_000)?;
        let selected = u64::try_from(sample.selected_item_fingerprints.len()).map_err(|_| {
            AuditError::Invalid {
                field: "selectedItemFingerprints",
                reason: "count exceeds supported range".to_owned(),
            }
        })?;
        if sample.population_size == 0
            || sample.sample_size == 0
            || sample.sample_size > sample.population_size
            || selected != sample.sample_size
            || (sample.method == SamplingMethod::FullPopulation
                && sample.sample_size != sample.population_size)
        {
            return invalid(
                "samplePlans",
                "population, sample size, and selection disagree",
            );
        }
        let mut fingerprints = BTreeSet::new();
        for fingerprint in &sample.selected_item_fingerprints {
            digest("selectedItemFingerprint", fingerprint)?;
            if !fingerprints.insert(fingerprint) {
                return invalid("samplePlans", "selected fingerprints must be unique");
            }
        }
    }
    Ok(sample_plans)
}

fn validate_workpapers(
    engagement: &AuditEngagement,
    actors: &BTreeMap<&str, &EngagementActor>,
    sample_plans: &BTreeMap<&str, &SamplePlan>,
) -> Result<BTreeSet<String>, AuditError> {
    unique_by("workpapers", &engagement.workpapers, 10_000, |item| {
        &item.workpaper_id
    })?;
    let mut workpaper_rules = BTreeSet::new();
    let mut exception_ids = BTreeSet::new();
    for workpaper in &engagement.workpapers {
        validate_workpaper(workpaper, actors, sample_plans, &mut workpaper_rules)?;
        for exception in &workpaper.exceptions {
            identifier("exceptionId", &exception.exception_id)?;
            if !exception_ids.insert(exception.exception_id.clone()) {
                return invalid("exceptions", "exception identifiers must be unique");
            }
            text("exception title", &exception.title, 500)?;
            text("exception description", &exception.description, 8_000)?;
            unique_identifiers(
                "exception evidenceExternalIds",
                &exception.evidence_external_ids,
                10_000,
                true,
            )?;
        }
    }
    Ok(exception_ids)
}

fn validate_workpaper(
    workpaper: &Workpaper,
    actors: &BTreeMap<&str, &EngagementActor>,
    sample_plans: &BTreeMap<&str, &SamplePlan>,
    workpaper_rules: &mut BTreeSet<String>,
) -> Result<(), AuditError> {
    identifier("workpaperId", &workpaper.workpaper_id)?;
    identifier("workpaper ruleId", &workpaper.rule_id)?;
    if !workpaper_rules.insert(workpaper.rule_id.clone()) {
        return invalid("workpapers", "only one workpaper may test each rule");
    }
    require_actor(actors, &workpaper.preparer_id, "workpaper preparer")?;
    timestamp("preparedAt", workpaper.prepared_at)?;
    text("procedurePerformed", &workpaper.procedure_performed, 8_000)?;
    unique_identifiers(
        "workpaper evidenceExternalIds",
        &workpaper.evidence_external_ids,
        10_000,
        true,
    )?;
    if let Some(sample_plan_id) = &workpaper.sample_plan_id {
        let Some(sample) = sample_plans.get(sample_plan_id.as_str()) else {
            return invalid("samplePlanId", "references an unknown sample plan");
        };
        if sample.rule_id != workpaper.rule_id {
            return invalid("samplePlanId", "sample plan tests a different rule");
        }
    }
    if let Some(signoff) = &workpaper.reviewer_signoff {
        require_actor(actors, &signoff.reviewer_id, "workpaper reviewer")?;
        if signoff.reviewer_id == workpaper.preparer_id {
            return invalid("reviewerId", "reviewer must differ from preparer");
        }
        timestamp("reviewedAt", signoff.reviewed_at)?;
        if signoff.reviewed_at < workpaper.prepared_at {
            return invalid("reviewedAt", "cannot precede workpaper preparation");
        }
        optional_text("review note", &signoff.note, 4_000)?;
    }
    Ok(())
}

fn validate_responses(
    engagement: &AuditEngagement,
    actors: &BTreeMap<&str, &EngagementActor>,
    exception_ids: &BTreeSet<String>,
) -> Result<BTreeSet<String>, AuditError> {
    unique_by(
        "managementResponses",
        &engagement.management_responses,
        10_000,
        |item| &item.response_id,
    )?;
    let mut response_exceptions = BTreeSet::new();
    for response in &engagement.management_responses {
        identifier("responseId", &response.response_id)?;
        if !exception_ids.contains(&response.exception_id) {
            return invalid(
                "exceptionId",
                "management response references unknown exception",
            );
        }
        if !response_exceptions.insert(response.exception_id.clone()) {
            return invalid(
                "managementResponses",
                "only one response is allowed per exception",
            );
        }
        require_actor(actors, &response.owner_id, "management response owner")?;
        text("management response", &response.response, 8_000)?;
        text("actionPlan", &response.action_plan, 8_000)?;
        timestamp("response dueAt", response.due_at)?;
    }
    Ok(response_exceptions)
}

fn validate_events(
    engagement: &AuditEngagement,
    actors: &BTreeMap<&str, &EngagementActor>,
) -> Result<(), AuditError> {
    for (expected, event) in (0_u64..).zip(&engagement.events) {
        if event.sequence != expected {
            return invalid("events", "sequences must be contiguous and start at zero");
        }
        identifier("eventType", &event.event_type)?;
        require_actor(actors, &event.actor_id, "event actor")?;
        timestamp("event occurredAt", event.occurred_at)?;
        identifier("event subjectId", &event.subject_id)?;
        digest("payloadSha256", &event.payload_sha256)?;
    }
    Ok(())
}

fn unique_by<'a, T, F>(
    field: &'static str,
    values: &'a [T],
    maximum: usize,
    key: F,
) -> Result<BTreeMap<&'a str, &'a T>, AuditError>
where
    F: Fn(&'a T) -> &'a str,
{
    if values.len() > maximum {
        return invalid(field, &format!("may contain at most {maximum} values"));
    }
    let mut result = BTreeMap::new();
    for value in values {
        if result.insert(key(value), value).is_some() {
            return invalid(field, "contains duplicate identifiers");
        }
    }
    Ok(result)
}

fn require_actor(
    actors: &BTreeMap<&str, &EngagementActor>,
    actor_id: &str,
    field: &'static str,
) -> Result<(), AuditError> {
    identifier(field, actor_id)?;
    if actors.contains_key(actor_id) {
        Ok(())
    } else {
        invalid(field, "references an unknown engagement actor")
    }
}

fn period(value: &AssessmentPeriod) -> Result<(), AuditError> {
    if value.starts_at < 0 || value.ends_at < value.starts_at {
        invalid("period", "requires 0 <= startsAt <= endsAt")
    } else {
        Ok(())
    }
}

fn timestamp(field: &'static str, value: i64) -> Result<(), AuditError> {
    if value < 0 {
        invalid(field, "must be a non-negative Unix timestamp")
    } else {
        Ok(())
    }
}

fn identifier(field: &'static str, value: &str) -> Result<(), AuditError> {
    if value.is_empty()
        || value.len() > 160
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'@')
        })
    {
        invalid(field, "must contain 1..=160 safe identifier bytes")
    } else {
        Ok(())
    }
}

fn scope(field: &'static str, value: &str) -> Result<(), AuditError> {
    if value.is_empty()
        || value.len() > 240
        || value.starts_with('/')
        || value.ends_with('/')
        || value.split('/').any(|segment| {
            segment.is_empty()
                || matches!(segment, "." | "..")
                || !segment.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'@')
                })
        })
    {
        invalid(field, "must be a safe relative hierarchical identifier")
    } else {
        Ok(())
    }
}

fn text(field: &'static str, value: &str, maximum: usize) -> Result<(), AuditError> {
    if value.is_empty()
        || value.len() > maximum
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        invalid(
            field,
            &format!("must be trimmed text containing 1..={maximum} bytes"),
        )
    } else {
        Ok(())
    }
}

fn optional_text(field: &'static str, value: &str, maximum: usize) -> Result<(), AuditError> {
    if value.is_empty() {
        Ok(())
    } else {
        text(field, value, maximum)
    }
}

fn unique_identifiers(
    field: &'static str,
    values: &[String],
    maximum: usize,
    empty_allowed: bool,
) -> Result<(), AuditError> {
    if (!empty_allowed && values.is_empty()) || values.len() > maximum {
        return invalid(field, &format!("requires 1..={maximum} unique values"));
    }
    let mut unique = BTreeSet::new();
    for value in values {
        identifier(field, value)?;
        if !unique.insert(value) {
            return invalid(field, "contains duplicate values");
        }
    }
    Ok(())
}

fn unique_text(
    field: &'static str,
    values: &[String],
    maximum: usize,
    empty_allowed: bool,
) -> Result<(), AuditError> {
    if (!empty_allowed && values.is_empty()) || values.len() > maximum {
        return invalid(field, &format!("requires 1..={maximum} unique values"));
    }
    let mut unique = BTreeSet::new();
    for value in values {
        text(field, value, 320)?;
        if !unique.insert(value) {
            return invalid(field, "contains duplicate values");
        }
    }
    Ok(())
}

fn digest(field: &'static str, value: &str) -> Result<(), AuditError> {
    let Some(hexadecimal) = value.strip_prefix("sha256:") else {
        return invalid(
            field,
            "must use sha256:<64 lowercase hexadecimal characters>",
        );
    };
    if hexadecimal.len() != 64
        || !hexadecimal
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        invalid(
            field,
            "must use sha256:<64 lowercase hexadecimal characters>",
        )
    } else {
        Ok(())
    }
}

fn invalid<T>(field: &'static str, reason: &str) -> Result<T, AuditError> {
    Err(AuditError::Invalid {
        field,
        reason: reason.to_owned(),
    })
}
