//! Independent customer declarations. Evidence contents are never fetched.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

use super::{Exit, write_output};
use crate::AuditError;
use crate::cli::{ReadinessArgs, ReportFormat};

const MAX_BYTES: u64 = 1_048_576;
const VERSION: &str = "canonical.readiness-response/v1";
const NOTICE: &str = "Customer declarations and evidence references only. Evidence contents, operating effectiveness, applicability and reviewer identity have not been verified. This is not certification, attestation, authorization or a legal opinion.";

#[derive(Deserialize)]
struct Catalog {
    version: String,
    frameworks: Vec<Framework>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Framework {
    id: String,
    title: String,
    edition: String,
    scope_note: String,
    sources: Vec<String>,
    questions: Vec<Question>,
}

#[derive(Deserialize)]
struct Question {
    id: String,
    prompt: String,
    evidence: String,
    method: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Context {
    customer_id: String,
    assessment_id: String,
    scope: String,
    period_start: String,
    period_end: String,
    as_of: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Response {
    schema_version: String,
    catalog_version: String,
    framework_id: String,
    context: Context,
    answers: Vec<Answer>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Status {
    Unanswered,
    Implemented,
    Partial,
    Missing,
    NotApplicable,
}

impl Status {
    fn label(self) -> &'static str {
        match self {
            Self::Unanswered => "unanswered",
            Self::Implemented => "implemented",
            Self::Partial => "partial",
            Self::Missing => "missing",
            Self::NotApplicable => "not_applicable",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Answer {
    question_id: String,
    status: Status,
    owner: String,
    notes: String,
    evidence_ref: String,
    evidence_date: String,
    reviewer: String,
    due_date: String,
}

#[derive(Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct Summary {
    total: usize,
    answered: usize,
    declared_gaps: usize,
    unknown_evidence: usize,
    incomplete_metadata: usize,
    review_pending: usize,
    overdue_actions: usize,
}

fn invalid() -> AuditError {
    AuditError::Invalid {
        field: "readiness",
        reason: "invalid packet, framework/version, context, answer, date or input limit".to_owned(),
    }
}

fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, AuditError> {
    if bytes.len() > 1_048_576 {
        return Err(invalid());
    }
    serde_json::from_slice(bytes).map_err(|_| invalid())
}

fn read<T: DeserializeOwned>(path: &Path) -> Result<T, AuditError> {
    let file = File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err(invalid());
    }
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1).read_to_end(&mut bytes)?;
    decode(&bytes)
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
}

fn text(value: &str, maximum: usize) -> bool {
    value.chars().count() <= maximum
        && !value
            .chars()
            .any(|ch| ch.is_ascii_control() && !matches!(ch, '\t' | '\n' | '\r'))
}

// Match ECMAScript String.trim rather than Rust's different Unicode whitespace set.
fn blank_text(value: &str) -> bool {
    value.chars().all(|ch| {
        matches!(
            ch,
            '\u{0009}'..='\u{000d}'
                | '\u{0020}'
                | '\u{00a0}'
                | '\u{1680}'
                | '\u{2000}'..='\u{200a}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202f}'
                | '\u{205f}'
                | '\u{3000}'
                | '\u{feff}'
        )
    })
}

fn valid_date(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes
            .iter()
            .enumerate()
            .any(|(index, byte)| !matches!(index, 4 | 7) && !byte.is_ascii_digit())
    {
        return false;
    }
    let number = |start: usize, end: usize| {
        bytes[start..end]
            .iter()
            .fold(0_u32, |value, byte| value * 10 + u32::from(byte - b'0'))
    };
    let year = number(0, 4);
    let month = number(5, 7);
    let day = number(8, 10);
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let maximum = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => 0,
    };
    year >= 1900 && day > 0 && day <= maximum
}

fn validate_context(context: &Context) -> Result<(), AuditError> {
    if !identifier(&context.customer_id)
        || !identifier(&context.assessment_id)
        || !text(&context.scope, 1000)
        || blank_text(&context.scope)
        || !valid_date(&context.period_start)
        || !valid_date(&context.period_end)
        || !valid_date(&context.as_of)
        || context.period_start > context.period_end
        || context.period_end > context.as_of
    {
        return Err(invalid());
    }
    Ok(())
}

fn blank(question: &Question) -> Answer {
    Answer {
        question_id: question.id.clone(),
        status: Status::Unanswered,
        owner: String::new(),
        notes: String::new(),
        evidence_ref: String::new(),
        evidence_date: String::new(),
        reviewer: String::new(),
        due_date: String::new(),
    }
}

fn draft(catalog: &Catalog, framework: &Framework, context: &Context) -> Response {
    Response {
        schema_version: VERSION.to_owned(),
        catalog_version: catalog.version.clone(),
        framework_id: framework.id.clone(),
        context: context.clone(),
        answers: framework.questions.iter().map(blank).collect(),
    }
}

fn validate_answer(answer: &Answer, context: &Context) -> bool {
    text(&answer.owner, 128)
        && text(&answer.reviewer, 128)
        && text(&answer.notes, 4000)
        && (answer.evidence_ref.is_empty() || identifier(&answer.evidence_ref))
        && (answer.evidence_date.is_empty() || valid_date(&answer.evidence_date))
        && answer.evidence_date <= context.as_of
        && (answer.due_date.is_empty() || valid_date(&answer.due_date))
}

fn validate(
    catalog: &Catalog,
    framework: &Framework,
    context: &Context,
    response: &Response,
) -> Result<(), AuditError> {
    validate_context(context)?;
    if response.schema_version != VERSION
        || response.catalog_version != catalog.version
        || response.framework_id != framework.id
        || response.context != *context
        || response.answers.len() > framework.questions.len()
    {
        return Err(invalid());
    }
    let known: BTreeSet<_> = framework.questions.iter().map(|q| &q.id).collect();
    let mut seen = BTreeSet::new();
    for answer in &response.answers {
        if !known.contains(&answer.question_id)
            || !seen.insert(&answer.question_id)
            || !validate_answer(answer, context)
        {
            return Err(invalid());
        }
    }
    Ok(())
}

fn answer_issues(answer: &Answer, as_of: &str, summary: &mut Summary) -> Vec<&'static str> {
    let mut issues = Vec::new();
    if answer.status == Status::Unanswered {
        issues.push("unanswered");
        return issues;
    }
    summary.answered += 1;
    if blank_text(&answer.owner) || blank_text(&answer.notes) {
        issues.push("owner_or_explanation_missing");
    }
    if blank_text(&answer.reviewer) {
        issues.push("assessor_review_pending");
        summary.review_pending += 1;
    }
    if answer.status == Status::Implemented
        && (answer.evidence_ref.is_empty() || answer.evidence_date.is_empty())
    {
        issues.push("evidence_unknown");
        summary.unknown_evidence += 1;
    }
    if matches!(answer.status, Status::Partial | Status::Missing) {
        summary.declared_gaps += 1;
        issues.push("declared_gap");
        if answer.due_date.is_empty() {
            issues.push("remediation_date_missing");
        } else if answer.due_date.as_str() < as_of {
            issues.push("remediation_overdue");
            summary.overdue_actions += 1;
        }
    }
    if answer.status == Status::NotApplicable && blank_text(&answer.reviewer) {
        issues.push("applicability_review_missing");
    }
    if issues.iter().any(|issue| {
        matches!(
            *issue,
            "owner_or_explanation_missing"
                | "remediation_date_missing"
                | "applicability_review_missing"
        )
    }) {
        summary.incomplete_metadata += 1;
    }
    issues
}

fn analyze(framework: &Framework, response: &Response) -> (Value, bool) {
    let mut summary = Summary::default();
    let mut items = Vec::new();
    for question in &framework.questions {
        summary.total += 1;
        let missing = blank(question);
        let answer = response
            .answers
            .iter()
            .find(|answer| answer.question_id == question.id)
            .unwrap_or(&missing);
        let issues = answer_issues(answer, &response.context.as_of, &mut summary);
        items.push(json!({"questionId": question.id, "status": answer.status, "issues": issues}));
    }
    let gaps = summary.answered < summary.total
        || summary.declared_gaps > 0
        || summary.unknown_evidence > 0
        || summary.incomplete_metadata > 0;
    let report = json!({
        "schemaVersion": "canonical.readiness-report/v1",
        "catalogVersion": response.catalog_version,
        "frameworkId": framework.id,
        "context": response.context,
        "summary": summary,
        "items": items,
        "declaredGapsOrUnknowns": gaps,
        "assurance": "none",
        "notice": NOTICE
    });
    (report, gaps)
}

fn escaped(value: &str) -> String {
    let mut result = String::new();
    for ch in value.chars() {
        match ch {
            '&' => result.push_str("&amp;"),
            '<' => result.push_str("&lt;"),
            '>' => result.push_str("&gt;"),
            '\n' | '\r' | '\t' => result.push(' '),
            ch if "\\`*_{}[]()#+.!|~-".contains(ch) => {
                result.push('\\');
                result.push(ch);
            }
            ch => result.push(ch),
        }
    }
    result
}

fn markdown(framework: &Framework, response: &Response, report: &Value) -> String {
    let mut output = format!(
        "# {} readiness checklist\n\nEdition: {}. Catalog: {}.\n\n{}\n\n{}\n\nComplete this framework independently. Missing evidence is unknown, not proof of failure.\n\n",
        framework.title, framework.edition, response.catalog_version, framework.scope_note, NOTICE
    );
    let context = &response.context;
    for (name, value) in [
        ("customerId", &context.customer_id),
        ("assessmentId", &context.assessment_id),
        ("scope", &context.scope),
        ("periodStart", &context.period_start),
        ("periodEnd", &context.period_end),
        ("asOf", &context.as_of),
    ] {
        let _ = writeln!(output, "{name}: {}\n", escaped(value));
    }
    let _ = writeln!(output, "Summary: {}\n", report["summary"]);
    for question in &framework.questions {
        let missing = blank(question);
        let answer = response
            .answers
            .iter()
            .find(|answer| answer.question_id == question.id)
            .unwrap_or(&missing);
        let _ = writeln!(
            output,
            "## {} — {}\n\nSuggested evidence: {}\n\nPrimary review method: {}.\n",
            question.id, question.prompt, question.evidence, question.method
        );
        for (name, value) in [
            ("status", answer.status.label()),
            ("owner", answer.owner.as_str()),
            ("notes", answer.notes.as_str()),
            ("evidenceRef", answer.evidence_ref.as_str()),
            ("evidenceDate", answer.evidence_date.as_str()),
            ("reviewer", answer.reviewer.as_str()),
            ("dueDate", answer.due_date.as_str()),
        ] {
            let _ = writeln!(output, "{name}: {}\n", escaped(value));
        }
    }
    output.push_str("## Authoritative references\n\n");
    for source in &framework.sources {
        let _ = writeln!(output, "- {source}");
    }
    output
}

pub(super) fn execute(arguments: &ReadinessArgs) -> Result<Exit, AuditError> {
    let catalog: Catalog = serde_json::from_str(include_str!("../../readiness/catalog.json"))?;
    let framework = catalog
        .frameworks
        .iter()
        .find(|framework| framework.id == arguments.framework)
        .ok_or_else(invalid)?;
    let context: Context = read(&arguments.context)?;
    validate_context(&context)?;
    let response: Response = match &arguments.responses {
        Some(path) => read(path)?,
        None => draft(&catalog, framework, &context),
    };
    validate(&catalog, framework, &context, &response)?;
    let (report, gaps) = analyze(framework, &response);
    let output = match arguments.format {
        ReportFormat::Json if arguments.responses.is_none() => {
            format!("{}\n", serde_json::to_string_pretty(&response)?)
        }
        ReportFormat::Json => format!("{}\n", serde_json::to_string_pretty(&report)?),
        ReportFormat::Markdown => markdown(framework, &response, &report),
    };
    write_output(&arguments.output, &output)?;
    Ok(if arguments.responses.is_some() && gaps {
        Exit::FindingThreshold
    } else {
        Exit::Success
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_javascript_fixtures_have_identical_semantics() -> Result<(), AuditError> {
        let catalog: Catalog = serde_json::from_str(include_str!("../../readiness/catalog.json"))?;
        let context: Context = decode(include_bytes!("../../readiness/context.example.json"))?;
        let fixtures: Value = serde_json::from_str(include_str!("../../readiness/fixtures.json"))?;
        let cases = fixtures.as_array().ok_or_else(invalid)?;
        for case in cases {
            let response: Response = serde_json::from_value(case["response"].clone())?;
            let framework = catalog
                .frameworks
                .iter()
                .find(|item| item.id == response.framework_id)
                .ok_or_else(invalid)?;
            validate(&catalog, framework, &context, &response)?;
            assert_eq!(analyze(framework, &response).0, case["report"]);
        }
        Ok(())
    }

    #[test]
    fn every_framework_is_independent_and_inputs_fail_closed() -> Result<(), AuditError> {
        let catalog: Catalog = serde_json::from_str(include_str!("../../readiness/catalog.json"))?;
        let context: Context = decode(include_bytes!("../../readiness/context.example.json"))?;
        assert_eq!(catalog.frameworks.len(), 15);
        for framework in &catalog.frameworks {
            let response = draft(&catalog, framework, &context);
            validate(&catalog, framework, &context, &response)?;
            assert_eq!(response.answers.len(), 10);
            let (report, gaps) = analyze(framework, &response);
            assert!(gaps);
            assert_eq!(report["assurance"], "none");
            let mut wrong = response.clone();
            wrong.context.customer_id = "other-customer".to_owned();
            assert!(validate(&catalog, framework, &context, &wrong).is_err());
            wrong = response.clone();
            wrong.framework_id = "other-framework".to_owned();
            assert!(validate(&catalog, framework, &context, &wrong).is_err());
            wrong = response.clone();
            wrong.answers[1].question_id.clone_from(&response.answers[0].question_id);
            assert!(validate(&catalog, framework, &context, &wrong).is_err());
            wrong = response;
            wrong.answers[0].evidence_ref = "https://example.invalid/private?credential=x".to_owned();
            assert!(validate(&catalog, framework, &context, &wrong).is_err());
        }
        Ok(())
    }

    #[test]
    fn dates_and_markdown_are_fail_closed() {
        for value in ["2026-02-29", "1899-12-31", "2026-13-01", "2026-01-00", "2026-1-01"] {
            assert!(!valid_date(value));
        }
        assert!(blank_text("\u{feff}"));
        assert!(!blank_text("\u{0085}"));
        assert!(valid_date("2024-02-29"));
        assert!(!valid_date("1900-02-29"));
        assert!(valid_date("2000-02-29"));
        assert_eq!(escaped("<img>\n![x](y)"), "&lt;img&gt; \\!\\[x\\]\\(y\\)");
    }

    #[test]
    fn duplicate_fields_and_unpaired_surrogates_are_rejected() {
        assert!(decode::<Context>(br#"{"customerId":"x","customerId":"y"}"#).is_err());
        assert!(decode::<String>(br#""\ud800""#).is_err());
        assert!(decode::<Value>(&vec![b' '; 1_048_577]).is_err());
    }
}
