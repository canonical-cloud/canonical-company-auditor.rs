import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createDraft, importDraft, validate, analyze, markdown, validDate, parseResponse } from './readiness.mjs';
const catalog = JSON.parse(await readFile(new URL('./catalog.json', import.meta.url), 'utf8'));
const context = JSON.parse(await readFile(new URL('./context.example.json', import.meta.url), 'utf8'));
const fresh = () => createDraft(catalog, 'soc2', context);
const roundtrip = (draft) => importDraft(catalog, 'soc2', context, JSON.stringify(draft));

test('catalog has fifteen independent, versioned frameworks and 150 original questions', () => {
  assert.equal(catalog.frameworks.length, 15);
  const ids = new Set();
  for (const f of catalog.frameworks) {
    assert.ok(f.edition && f.scopeNote); assert.ok(f.sources.every((url) => url.startsWith('https://')));
    assert.equal(f.questions.length, 10);
    for (const q of f.questions) { assert.ok(q.id.startsWith(`${f.id}.`)); assert.ok(!ids.has(q.id)); ids.add(q.id); assert.ok(q.prompt && q.evidence); assert.ok(['examine', 'interview', 'test'].includes(q.method)); }
  }
  assert.equal(ids.size, 150);
});
for (const f of catalog.frameworks) test(`${f.id}: blank, independent, serializable and never assured`, () => {
  const draft = createDraft(catalog, f.id, context);
  assert.ok(draft.answers.every((a) => a.status === 'unanswered' && a.evidenceRef === ''));
  assert.deepEqual(importDraft(catalog, f.id, context, JSON.stringify(draft)), draft);
  const report = analyze(catalog, f.id, context, draft);
  assert.equal(report.summary.answered, 0); assert.equal(report.summary.total, 10); assert.equal(report.assurance, 'none'); assert.equal(report.declaredGapsOrUnknowns, true);
  assert.ok(markdown(catalog, f.id, context, draft).includes(f.questions[0].id));
});
test('mutating one framework cannot answer another or change caller context', () => {
  const soc = fresh(), iso = createDraft(catalog, 'iso27001', context);
  soc.answers[0].status = 'implemented'; soc.context.scope = 'different';
  assert.equal(iso.answers[0].status, 'unanswered'); assert.equal(context.scope, iso.context.scope);
});
for (const field of ['customerId', 'assessmentId', 'scope', 'periodStart', 'periodEnd', 'asOf']) test(`rejects a mismatched ${field}`, () => {
  const draft = fresh(); draft.context[field] = field.endsWith('Id') ? 'other' : field === 'scope' ? 'other' : '2026-08-02';
  assert.throws(() => roundtrip(draft));
});
for (const [field, value] of [['schemaVersion', 'unknown'], ['catalogVersion', 'old'], ['frameworkId', 'gdpr']]) test(`rejects mismatched ${field}`, () => {
  const draft = fresh(); draft[field] = value; assert.throws(() => roundtrip(draft));
});
test('cannot inject answers from another framework, duplicates or unknown questions', () => {
  for (const change of [(d) => { d.answers[0].questionId = 'gdpr.q01'; }, (d) => { d.answers[1].questionId = d.answers[0].questionId; }, (d) => { d.answers[0].questionId = 'soc2.q99'; }]) { const d = fresh(); change(d); assert.throws(() => roundtrip(d)); }
});
test('missing answers stay unanswered and are not dropped from the denominator', () => {
  const d = fresh(); d.answers = [];
  const report = analyze(catalog, 'soc2', context, d); assert.equal(report.summary.total, 10); assert.equal(report.summary.answered, 0);
  assert.equal(roundtrip(d).answers.length, 10);
});
test('unknown fields and incorrect types fail closed', () => {
  for (const change of [(d) => { d.extra = true; }, (d) => { d.context.ownerId = 'spoof'; }, (d) => { d.answers[0].approved = true; }, (d) => { d.answers[0].status = true; }, (d) => { d.answers[0].notes = {}; }]) { const d = fresh(); change(d); assert.throws(() => roundtrip(d)); }
});
test('missing evidence is unknown rather than a proven failed control', () => {
  const d = fresh(); Object.assign(d.answers[0], { status: 'implemented', owner: 'Owner', notes: 'Description' });
  const report = analyze(catalog, 'soc2', context, d); assert.equal(report.summary.unknownEvidence, 1); assert.equal(report.summary.declaredGaps, 0); assert.equal(report.assurance, 'none');
});
test('N/A needs a reason, owner and reviewer; it cannot silently close a question', () => {
  const d = fresh(); d.answers[0].status = 'not_applicable';
  assert.equal(analyze(catalog, 'soc2', context, d).summary.incompleteMetadata, 1);
  Object.assign(d.answers[0], { owner: 'Owner', notes: 'Scoped applicability rationale', reviewer: 'Assessor' });
  assert.equal(analyze(catalog, 'soc2', context, d).summary.incompleteMetadata, 0);
});
test('declared gaps and overdue corrective actions remain visible', () => {
  const d = fresh(); Object.assign(d.answers[0], { status: 'partial', owner: 'Owner', notes: 'Gap', dueDate: '2026-09-01' });
  const s = analyze(catalog, 'soc2', context, d).summary; assert.equal(s.declaredGaps, 1); assert.equal(s.overdueActions, 1);
});
test('fully populated self-reports still do not establish assurance or reviewer identity', () => {
  const d = fresh(); for (const a of d.answers) Object.assign(a, { status: 'implemented', owner: 'Owner', notes: 'Description', evidenceRef: 'vault:artifact-123', evidenceDate: '2026-08-31' });
  const r = analyze(catalog, 'soc2', context, d); assert.equal(r.declaredGapsOrUnknowns, false); assert.equal(r.summary.reviewPending, 10); assert.equal(r.assurance, 'none'); assert.match(r.notice, /have not been verified/);
});
test('calendar validation rejects impossible, future-collected and inverted dates', () => {
  assert.equal(validDate('2024-02-29'), true);
  for (const date of ['2026-02-29', '2026-04-31', '2026-9-01', '0000-01-01', '2026-09-01T00:00:00Z']) assert.equal(validDate(date), false);
  const d = fresh(); d.answers[0].evidenceDate = '2026-09-08'; assert.throws(() => roundtrip(d));
  assert.throws(() => createDraft(catalog, 'soc2', { ...context, periodEnd: '2026-12-31' }));
});
test('raw evidence URLs, oversize fields and control characters are refused', () => {
  for (const change of [(d) => { d.answers[0].evidenceRef = 'https://example.com/signed?secret=abc'; }, (d) => { d.answers[0].notes = 'a'.repeat(4001); }, (d) => { d.answers[0].notes = '\u0000'; }, (d) => { d.context.customerId = 'customer with spaces'; }]) { const d = fresh(); change(d); assert.throws(() => roundtrip(d)); }
});
test('input bytes, malformed JSON, duplicate keys and deep nesting are rejected', () => {
  assert.throws(() => importDraft(catalog, 'soc2', context, 'x'.repeat(1048577)));
  assert.throws(() => parseResponse('{broken'));
  for (const input of ['{"a":1,"a":2}', '{"a":1,"\\u0061":2}', '{"a":{"b":1,"b":2}}', '['.repeat(40) + '0' + ']'.repeat(40)]) assert.throws(() => parseResponse(input));
  assert.deepEqual(parseResponse('{"a":["escaped \\\" quote",true,null,-3.4e2]}'), { a: ['escaped " quote', true, null, -340] });
});
test('Markdown escapes customer HTML, image markup and multiline heading injection', () => {
  const d = fresh(); d.answers[0].notes = '<script>alert(1)</script>\n# forged ![remote](https://example.com/x)';
  const output = markdown(catalog, 'soc2', context, d);
  assert.ok(!output.includes('<script>')); assert.ok(!output.includes('\n# forged')); assert.ok(!output.includes('![remote]('));
});
test('UI has no inline script or unsafe dynamic HTML/persistent storage sink', async () => {
  const html = await readFile(new URL('./index.html', import.meta.url), 'utf8'), script = await readFile(new URL('./browser.mjs', import.meta.url), 'utf8');
  assert.ok(html.includes('role="alert"')); assert.ok(html.includes('type="module"'));
  assert.doesNotMatch(script, /innerHTML|outerHTML|insertAdjacentHTML|localStorage|sessionStorage|indexedDB/);
  assert.doesNotMatch(html, /<script[^>]*>\s*[^<\s]|\son(?:click|load|submit)=/);
});

test('Unicode scalar validation matches Rust without rejecting emoji', () => {
  const d = fresh(); d.answers[0].notes = '\ud800'; assert.throws(() => roundtrip(d));
  d.answers[0].notes = 'Valid 😀'; assert.equal(roundtrip(d).answers[0].notes, d.answers[0].notes);
});
test('shared Rust golden fixtures match JavaScript reports exactly', async () => {
  const fixtures = JSON.parse(await readFile(new URL('./fixtures.json', import.meta.url), 'utf8'));
  for (const { response, report } of fixtures) assert.deepEqual(analyze(catalog, response.frameworkId, response.context, response), report);
});

test('browser decoder rejects malformed UTF-8 and preserves BOM for JSON rejection', () => {
  const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
  assert.throws(() => decoder.decode(Uint8Array.from([0xff])));
  assert.throws(() => parseResponse(decoder.decode(Uint8Array.from([0xef, 0xbb, 0xbf, 0x7b, 0x7d]))));
});
