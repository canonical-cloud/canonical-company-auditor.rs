import test from 'node:test';
import assert from 'node:assert/strict';
import { createDraft, importDraft, analyze, workpaper, hasAnswerEdits, exclusiveOperation, visibleQuestionIds, QUESTION_VIEWS } from './readiness.mjs';

// Synthetic fixtures keep these edge-case tests hermetic. The separate existing
// readiness.test.mjs checks the real fifteen-framework catalog and golden reports.
const context = { customerId: 'acme', assessmentId: 'exercise', scope: 'Synthetic service', periodStart: '2026-08-01', periodEnd: '2026-08-31', asOf: '2026-09-08' };
const catalog = { version: 'test.1', frameworks: ['soc2', 'gdpr'].map((id) => ({ id, title: id, edition: 'test edition', scopeNote: 'Synthetic, non-normative test fixture.', sources: [], questions: Array.from({ length: 10 }, (_, i) => ({ id: `${id}.q${String(i+1).padStart(2, '0')}`, prompt: `Question ${i+1}?`, evidence: 'Dated evidence', method: 'examine' })) })) };
const fresh = (id = 'soc2') => createDraft(catalog, id, context);
const report = (draft) => analyze(catalog, draft.frameworkId, context, draft);

test('blank template is the only draft without answer edits', () => assert.equal(hasAnswerEdits(fresh()), false));
for (const [field, value] of Object.entries({ status: 'partial', owner: 'Owner', notes: 'Explanation', evidenceRef: 'vault:e-1', evidenceDate: '2026-08-31', reviewer: 'Reviewer', dueDate: '2026-10-01' })) {
  test(`protects ${field}-only edits even before a declaration`, () => {
    const draft = fresh(); draft.answers[0][field] = value;
    assert.equal(hasAnswerEdits(draft), true);
    assert.equal(hasAnswerEdits(fresh('gdpr')), false);
  });
}
test('whitespace-only edits still require a replacement decision', () => {
  const draft = fresh(); draft.answers[0].notes = ' ';
  assert.equal(hasAnswerEdits(draft), true);
});

test('overlapping imports cannot run or overtake the first file read', async () => {
  const exclusive = exclusiveOperation(); let release; const applied = [];
  const pending = exclusive(async () => { await new Promise((resolve) => { release = resolve; }); applied.push('first'); });
  assert.equal(await exclusive(async () => { applied.push('second'); }), false);
  assert.deepEqual(applied, []); release(); assert.equal(await pending, true);
  assert.deepEqual(applied, ['first']);
  assert.equal(await exclusive(async () => { applied.push('third'); }), true);
  assert.deepEqual(applied, ['first', 'third']);
});
for (const failure of ['sync', 'async']) test(`import gate releases after ${failure} failure`, async () => {
  const exclusive = exclusiveOperation();
  const failing = failure === 'sync' ? () => { throw new Error('fixture'); } : async () => { await Promise.resolve(); throw new Error('fixture'); };
  await assert.rejects(exclusive(failing), /fixture/);
  assert.equal(await exclusive(() => {}), true);
});
test('cancelled replacement does not poison the next import', async () => {
  const exclusive = exclusiveOperation(); let changed = false;
  await exclusive(() => { if (!false) return; changed = true; });
  assert.equal(changed, false); await exclusive(() => { changed = true; }); assert.equal(changed, true);
});

function mixed() {
  const draft = fresh();
  Object.assign(draft.answers[0], { status: 'implemented', owner: 'Owner', notes: 'No evidence yet' });
  Object.assign(draft.answers[1], { status: 'partial', owner: 'Owner', notes: 'Gap', dueDate: '2026-09-01' });
  Object.assign(draft.answers[2], { status: 'missing', owner: 'Owner', notes: 'Gap', dueDate: '2026-10-01', reviewer: 'Reviewer' });
  return draft;
}
for (const [view, indices] of Object.entries({ all: [1,2,3,4,5,6,7,8,9,10], unanswered: [4,5,6,7,8,9,10], gaps: [2,3], evidence: [1], review: [1,2], overdue: [2] })) {
  test(`${view} view preserves the full report and denominator`, () => {
    const result = report(mixed()), before = structuredClone(result);
    assert.deepEqual([...visibleQuestionIds(result, view)], indices.map((i) => `soc2.q${String(i).padStart(2, '0')}`));
    assert.deepEqual(result, before); assert.equal(result.summary.total, 10);
  });
}
test('unknown views fail closed', () => assert.throws(() => visibleQuestionIds(report(fresh()), '__proto__'), /Unknown/));
test('view contract is immutable', () => assert.throws(() => QUESTION_VIEWS.push('auto_pass')));

test('workpaper starts every assessor result as not assessed, regardless of declarations', () => {
  const draft = fresh();
  for (const answer of draft.answers) Object.assign(answer, { status: 'implemented', owner: 'Owner', notes: 'Claim', evidenceRef: 'vault:e1', evidenceDate: '2026-08-31', reviewer: 'UNVERIFIED_REVIEWER_CANARY' });
  const before = structuredClone(draft), output = workpaper(catalog, 'soc2', context, draft);
  assert.equal((output.match(/Assessor outcome: not assessed/g) ?? []).length, 10);
  assert.equal((output.match(/Independent review: pending/g) ?? []).length, 10);
  assert.doesNotMatch(output, /UNVERIFIED_REVIEWER_CANARY|Assessor outcome: pass/);
  assert.match(output, /completeness reconciliation/); assert.match(output, /sample-size rationale/);
  assert.match(output, /Retest evidence/); assert.deepEqual(draft, before);
});
test('missing answers still produce every workpaper and never inherit N/A', () => {
  const draft = fresh(); draft.answers = [];
  assert.equal((workpaper(catalog, 'soc2', context, draft).match(/## Workpaper /g) ?? []).length, 10);
  const gdpr = fresh('gdpr'); gdpr.answers[0].status = 'not_applicable';
  const output = workpaper(catalog, 'gdpr', context, gdpr);
  assert.doesNotMatch(output, /soc2/); assert.match(output, /Assessor outcome: not assessed/);
});
test('workpapers reject customer, framework and revision mismatches', () => {
  for (const mutate of [(d) => { d.context.customerId = 'other'; }, (d) => { d.frameworkId = 'gdpr'; }, (d) => { d.catalogVersion = 'old'; }]) {
    const draft = fresh(); mutate(draft); assert.throws(() => workpaper(catalog, 'soc2', context, draft));
  }
});
test('workpaper escapes customer markup and does not include raw answer notes', () => {
  const ctx = { ...context, scope: '<img src=x>\n# injected' }, draft = createDraft(catalog, 'soc2', ctx);
  draft.answers[0].owner = '[click](https://example.invalid)'; draft.answers[0].notes = 'PRIVATE_NOTES_CANARY';
  const output = workpaper(catalog, 'soc2', ctx, draft);
  assert.doesNotMatch(output, /<img|\n# injected|\[click\]\(|PRIVATE_NOTES_CANARY/);
  assert.match(output, /&lt;img/);
});
test('failed import leaves the original response untouched', () => {
  const original = mixed(), before = structuredClone(original);
  assert.throws(() => importDraft(catalog, 'soc2', context, JSON.stringify({ ...original, frameworkId: 'gdpr' })));
  assert.deepEqual(original, before);
});
for (const suffix of ['\n', '\r', '\u2028', '\u2029']) test(`identifier boundary rejects trailing U+${suffix.charCodeAt(0).toString(16)}`, () => {
  assert.throws(() => createDraft(catalog, 'soc2', { ...context, customerId: 'acme' + suffix }));
});
