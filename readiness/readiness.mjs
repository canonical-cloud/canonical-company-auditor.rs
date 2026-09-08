// Shared, side-effect-free readiness contract. No persistence, network or inheritance.
export const RESPONSE_VERSION = 'canonical.readiness-response/v1';
export const MAX_BYTES = 1048576;
export const STATUSES = Object.freeze(['unanswered', 'implemented', 'partial', 'missing', 'not_applicable']);
const CONTEXT_KEYS = ['customerId', 'assessmentId', 'scope', 'periodStart', 'periodEnd', 'asOf'];
const ANSWER_KEYS = ['questionId', 'status', 'owner', 'notes', 'evidenceRef', 'evidenceDate', 'reviewer', 'dueDate'];
const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
function object(value, keys, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length !== keys.length || keys.some((key) => !Object.hasOwn(value, key))) throw new Error(`Invalid ${label} fields`);
}
function text(value, maximum, label, required = false) {
  if (typeof value !== 'string' || /[\uD800-\uDFFF]/u.test(value) || [...value].length > maximum || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(value) || (required && !value.trim())) throw new Error(`Invalid ${label}`);
}
export function validDate(value) {
  if (typeof value !== 'string' || !/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/.test(value) || value < '1900-01-01' || value > '9999-12-31') return false;
  const date = new Date(`${value}T00:00:00Z`);
  return Number.isFinite(date.getTime()) && date.toISOString().slice(0, 10) === value;
}
export function validateContext(context) {
  object(context, CONTEXT_KEYS, 'context');
  if (!ID.test(context.customerId) || !ID.test(context.assessmentId) || typeof context.customerId !== 'string' || typeof context.assessmentId !== 'string') throw new Error('Invalid customer or assessment identifier');
  text(context.scope, 1000, 'scope', true);
  for (const key of ['periodStart', 'periodEnd', 'asOf']) if (!validDate(context[key])) throw new Error('Invalid assessment date');
  if (context.periodStart > context.periodEnd || context.periodEnd > context.asOf) throw new Error('Evidence period must end on or before the as-of date');
}
export function framework(catalog, id) {
  const found = catalog.frameworks.find((item) => item.id === id);
  if (!found) throw new Error('Unknown framework');
  return found;
}
export function createDraft(catalog, id, context) {
  validateContext(context);
  return {
    schemaVersion: RESPONSE_VERSION, catalogVersion: catalog.version, frameworkId: id, context: { ...context },
    answers: framework(catalog, id).questions.map((question) => ({ questionId: question.id, status: 'unanswered', owner: '', notes: '', evidenceRef: '', evidenceDate: '', reviewer: '', dueDate: '' })),
  };
}
export function validate(catalog, id, context, draft) {
  validateContext(context);
  object(draft, ['schemaVersion', 'catalogVersion', 'frameworkId', 'context', 'answers'], 'response');
  if (draft.schemaVersion !== RESPONSE_VERSION || draft.catalogVersion !== catalog.version || draft.frameworkId !== id) throw new Error('Framework or version mismatch; answers cannot be inherited');
  validateContext(draft.context);
  if (CONTEXT_KEYS.some((key) => draft.context[key] !== context[key])) throw new Error('Customer, assessment, scope or evidence-period mismatch');
  const questions = framework(catalog, id).questions, known = new Set(questions.map((item) => item.id)), seen = new Set();
  if (!Array.isArray(draft.answers) || draft.answers.length > questions.length) throw new Error('Invalid answer collection');
  for (const answer of draft.answers) {
    object(answer, ANSWER_KEYS, 'answer');
    if (!known.has(answer.questionId) || seen.has(answer.questionId)) throw new Error('Unknown or duplicate question identifier');
    seen.add(answer.questionId);
    if (!STATUSES.includes(answer.status)) throw new Error('Invalid answer status');
    for (const key of ['owner', 'reviewer']) text(answer[key], 128, key);
    text(answer.notes, 4000, 'notes'); text(answer.evidenceRef, 128, 'evidence reference');
    if (answer.evidenceRef && !ID.test(answer.evidenceRef)) throw new Error('Use an opaque evidence identifier, not a URL or evidence contents');
    for (const key of ['evidenceDate', 'dueDate']) if (answer[key] !== '' && !validDate(answer[key])) throw new Error('Invalid evidence or remediation date');
    if (answer.evidenceDate > context.asOf) throw new Error('Evidence cannot be collected after the as-of date');
  }
  return draft;
}
export function parseResponse(raw) {
  if (typeof raw !== 'string' || new TextEncoder().encode(raw).length > MAX_BYTES) throw new Error('Response exceeds the 1 MiB limit');
  let parsed;
  try { parsed = JSON.parse(raw); } catch { throw new Error('Invalid response JSON'); }
  // Reject ambiguous duplicate object keys, including differently escaped keys.
  // JSON.parse alone silently keeps the last occurrence; Rust serde rejects it.
  const tokens = raw.match(/"(?:\\[\s\S]|[^"\\])*"|[{}\[\]:,]|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?|true|false|null/g) ?? [];
  let index = 0;
  function walk(depth) {
    if (depth > 32) throw new Error('Response nesting exceeds the limit');
    const token = tokens[index++];
    if (token === '{') {
      const keys = new Set();
      if (tokens[index] === '}') { index++; return; }
      while (true) {
        const key = JSON.parse(tokens[index++]);
        if (keys.has(key)) throw new Error('Duplicate JSON field');
        keys.add(key); index++; walk(depth + 1);
        if (tokens[index++] === '}') return;
      }
    }
    if (token === '[') {
      if (tokens[index] === ']') { index++; return; }
      while (true) { walk(depth + 1); if (tokens[index++] === ']') return; }
    }
  }
  walk(0);
  if (index !== tokens.length) throw new Error('Invalid response JSON');
  return parsed;
}
export function importDraft(catalog, id, context, raw) {
  const draft = parseResponse(raw);
  validate(catalog, id, context, draft);
  // Copy only the validated contract; missing answers remain explicitly unanswered.
  const result = createDraft(catalog, id, context), incoming = new Map(draft.answers.map((answer) => [answer.questionId, answer]));
  result.answers = result.answers.map((answer) => ({ ...(incoming.get(answer.questionId) ?? answer) }));
  return result;
}
export function analyze(catalog, id, context, draft) {
  validate(catalog, id, context, draft);
  const answers = new Map(draft.answers.map((answer) => [answer.questionId, answer]));
  const summary = { total: 0, answered: 0, declaredGaps: 0, unknownEvidence: 0, incompleteMetadata: 0, reviewPending: 0, overdueActions: 0 };
  const items = framework(catalog, id).questions.map((question) => {
    const answer = answers.get(question.id), status = answer?.status ?? 'unanswered';
    const issues = [];
    summary.total++;
    if (status === 'unanswered') issues.push('unanswered');
    else {
      summary.answered++;
      if (!answer.owner.trim() || !answer.notes.trim()) issues.push('owner_or_explanation_missing');
      if (!answer.reviewer.trim()) { issues.push('assessor_review_pending'); summary.reviewPending++; }
      if (status === 'implemented' && (!answer.evidenceRef || !answer.evidenceDate)) { issues.push('evidence_unknown'); summary.unknownEvidence++; }
      if (status === 'partial' || status === 'missing') {
        summary.declaredGaps++; issues.push('declared_gap');
        if (!answer.dueDate) issues.push('remediation_date_missing');
        else if (answer.dueDate < context.asOf) { issues.push('remediation_overdue'); summary.overdueActions++; }
      }
      if (status === 'not_applicable' && !answer.reviewer.trim()) issues.push('applicability_review_missing');
    }
    if (issues.some((issue) => ['owner_or_explanation_missing', 'remediation_date_missing', 'applicability_review_missing'].includes(issue))) summary.incompleteMetadata++;
    return { questionId: question.id, status, issues };
  });
  return {
    schemaVersion: 'canonical.readiness-report/v1', catalogVersion: catalog.version, frameworkId: id, context: { ...context }, summary, items,
    declaredGapsOrUnknowns: summary.answered < summary.total || summary.declaredGaps > 0 || summary.unknownEvidence > 0 || summary.incompleteMetadata > 0,
    assurance: 'none',
    notice: 'Customer declarations and evidence references only. Evidence contents, operating effectiveness, applicability and reviewer identity have not been verified. This is not certification, attestation, authorization or a legal opinion.',
  };
}
function markdownText(value) {
  return String(value).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/([\\`*_{}\[\]()#+.!|~-])/g, '\\$1').replace(/[\r\n\t]/g, ' ');
}
export function markdown(catalog, id, context, draft) {
  const result = analyze(catalog, id, context, draft), selected = framework(catalog, id);
  const answers = new Map(draft.answers.map((answer) => [answer.questionId, answer]));
  const lines = [`# ${selected.title} readiness checklist`, '', `Edition: ${selected.edition}. Catalog: ${catalog.version}.`, '', selected.scopeNote, '', result.notice, '', 'Complete this framework independently. Missing evidence is unknown, not proof of failure. Do not paste secrets, PHI, personal records or raw evidence here.', ''];
  for (const key of CONTEXT_KEYS) lines.push(`${key}: ${markdownText(context[key])}`, '');
  lines.push(`Answered: ${result.summary.answered}/${result.summary.total}. Declared gaps: ${result.summary.declaredGaps}. Unknown evidence: ${result.summary.unknownEvidence}. Incomplete metadata: ${result.summary.incompleteMetadata}. Review pending: ${result.summary.reviewPending}.`, '');
  for (const question of selected.questions) {
    const answer = answers.get(question.id);
    lines.push(`## ${question.id} — ${question.prompt}`, '', `Suggested evidence: ${question.evidence}`, '', `Primary review method: ${question.method}.`, '');
    for (const key of ANSWER_KEYS.filter((key) => key !== 'questionId')) lines.push(`${key}: ${markdownText(answer?.[key] ?? (key === 'status' ? 'unanswered' : ''))}`, '');
  }
  lines.push('## Authoritative references', '', ...selected.sources.map((url) => `- ${url}`), '');
  return lines.join('\n');
}

// A draft can contain valuable evidence/ownership work before its status changes.
export function hasAnswerEdits(draft) {
  return draft.answers.some((answer) => ANSWER_KEYS.some((key) =>
    key !== 'questionId' && answer[key] !== (key === 'status' ? 'unanswered' : '')));
}

// Only one file read/replacement may be active. Failed or cancelled operations
// release the gate; ignored overlapping calls cannot reset an active operation.
export function exclusiveOperation() {
  let active = false;
  return async (operation) => {
    if (active) return false;
    active = true;
    try { await operation(); return true; }
    finally { active = false; }
  };
}

export const QUESTION_VIEWS = Object.freeze(['all', 'unanswered', 'gaps', 'evidence', 'review', 'overdue']);
export function visibleQuestionIds(report, view) {
  if (!QUESTION_VIEWS.includes(view)) throw new Error('Unknown question view');
  const issue = { unanswered: 'unanswered', gaps: 'declared_gap', evidence: 'evidence_unknown', review: 'assessor_review_pending', overdue: 'remediation_overdue' }[view];
  return new Set(report.items.filter((item) => view === 'all' || item.issues.includes(issue)).map((item) => item.questionId));
}

// Planning template only: no customer declaration becomes an assessor result.
// The existing response contract remains the authoritative input boundary.
export function workpaper(catalog, id, context, draft) {
  const report = analyze(catalog, id, context, draft), selected = framework(catalog, id);
  const answers = new Map(draft.answers.map((answer) => [answer.questionId, answer]));
  const lines = [`# ${markdownText(selected.title)} pre-audit workpaper`, '',
    `Edition: ${markdownText(selected.edition)}. Catalog: ${markdownText(catalog.version)}.`, '',
    'Planning template; no assessment has been performed by this export. All assessor outcomes start as not assessed. Customer declarations, N/A decisions and reviewer names are not inherited as assurance.', '',
    report.notice, '', markdownText(selected.scopeNote), ''];
  for (const key of CONTEXT_KEYS) lines.push(`${key}: ${markdownText(context[key])}`, '');
  lines.push('## Engagement authorization and coverage', '',
    'Lead assessor / competence / independence: ____________________', '',
    'Applicable licensed/public requirement program and edition: ____________________', '',
    'Scope exclusions and approved applicability rationale: ____________________', '',
    'Written test authorization, allowed targets/operations, window and stop contact: ____________________', '',
    'Evidence repository access, minimization, retention and deletion agreement: ____________________', '',
    'These broad intake prompts must be expanded against the applicable full requirement program. Choose depth, coverage and sampling for this engagement; no universal sample count is implied.', '');
  for (const question of selected.questions) {
    const answer = answers.get(question.id);
    lines.push(`## Workpaper ${markdownText(question.id)}`, '',
      `Intake objective: ${markdownText(question.prompt)}`, '',
      `Customer declaration (unverified): ${markdownText(answer?.status ?? 'unanswered')}`, '',
      `Customer owner (unverified): ${markdownText(answer?.owner ?? '')}`, '',
      `Evidence request: ${markdownText(question.evidence)}`, '',
      `Existing opaque reference (unverified): ${markdownText(answer?.evidenceRef ?? '')}`, '',
      `Suggested primary method: ${markdownText(question.method)}; assessor confirms examine / interview / test and complementary methods.`, '',
      'Requirement reference / applicability / testable determination: ____________________', '',
      'Evidence-request owner / due date / observation period: ____________________', '',
      'Population definition / source query / size / completeness reconciliation: ____________________', '',
      'Selection method / risk strata / sample-size rationale / selected opaque item IDs: ____________________', '',
      'Zero-event population, substitutions and limitations: ____________________', '',
      'Authorized test steps / expected behavior / actual observation: ____________________', '',
      'Evidence IDs / collector / collected-at / tool version / integrity digest / redactions: ____________________', '',
      'Design evaluation / operating-period evidence / contradictions: ____________________', '',
      'Assessor outcome: not assessed', '',
      'Finding ID / risk / remediation owner / target date / retest criteria: ____________________', '',
      'Retest evidence and residual limitations: ____________________', '',
      'Independent review: pending; authenticated approval reference: ____________________', '');
  }
  lines.push('## Handoff', '',
    'Unresolved requests / exclusions / residual uncertainty: ____________________', '',
    'Qualified assessor recommendation and approval reference: ____________________', '',
    'Store completed workpapers in approved protected storage. Do not paste credentials, PHI or raw personal records. Completing this template is not certification or a legal opinion.', '',
    '## Methodology reference', '',
    'NIST assessment planning guidance (adapt to the selected framework; not a cross-framework control mapping): https://csrc.nist.gov/pubs/sp/800/53/a/r5/final', '');
  return lines.join('\n');
}
