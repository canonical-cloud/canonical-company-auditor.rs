import { createDraft, importDraft, analyze, markdown, workpaper, framework, STATUSES, MAX_BYTES, hasAnswerEdits, exclusiveOperation, visibleQuestionIds } from './readiness.mjs';
const $ = (id) => document.getElementById(id);
const fieldLabels = { status: 'Customer declaration', owner: 'Control or remediation owner', notes: 'Explanation / gap / N/A rationale', evidenceRef: 'Opaque evidence reference (no URLs)', evidenceDate: 'Evidence collection date', reviewer: 'Reviewer name (self-reported, not a verified approval)', dueDate: 'Remediation due date' };
const importExclusively = exclusiveOperation();
let catalog, selected, context, draft, dirty = false, importing = false, lastReport;
function error(message, focus = false) { $('error').textContent = message; if (message && focus) $('error').focus(); }
function fieldsValid() {
  for (const input of $('questions').querySelectorAll('input,textarea,select')) {
    if (!input.validity.valid) throw new Error('Complete or correct the highlighted field before exporting.');
  }
}
function applyView() {
  if (!lastReport) return;
  const visible = visibleQuestionIds(lastReport, $('question-view').value);
  for (const item of $('questions').children) item.hidden = !visible.has(item.dataset.questionId);
  $('visible-count').textContent = `Showing ${visible.size}/${lastReport.summary.total}. Exports and printing include every question.`;
}
function summarize() {
  try {
    fieldsValid();
    lastReport = analyze(catalog, selected.id, context, draft);
    const s = lastReport.summary;
    $('summary').textContent = `Answered ${s.answered}/${s.total} · Declared gaps ${s.declaredGaps} · Unknown evidence ${s.unknownEvidence} · Incomplete metadata ${s.incompleteMetadata} · Reviewer pending ${s.reviewPending} · Overdue ${s.overdueActions}. Customer declarations only; no assurance conclusion.`;
    applyView(); error('');
  } catch (cause) {
    // Never strand an invalid field behind a filter or leave a stale green summary.
    lastReport = undefined;
    for (const item of $('questions').children) item.hidden = false;
    $('summary').textContent = 'Draft has invalid or incomplete fields; no current summary is available.';
    $('visible-count').textContent = 'Showing every question until the invalid fields are corrected.';
    error(cause.message);
  }
}
function renderQuestions() {
  const fragment = document.createDocumentFragment();
  for (const question of selected.questions) {
    const answer = draft.answers.find((item) => item.questionId === question.id);
    const fieldset = document.createElement('fieldset'), legend = document.createElement('legend'), evidence = document.createElement('p'), grid = document.createElement('div');
    fieldset.className = 'editor'; fieldset.dataset.questionId = question.id; legend.textContent = `${question.id} — ${question.prompt}`;
    evidence.className = 'evidence'; evidence.textContent = `Suggested evidence: ${question.evidence} Primary review method: ${question.method}.`;
    grid.className = 'grid'; fieldset.append(legend, evidence, grid);
    for (const [key, title] of Object.entries(fieldLabels)) {
      const label = document.createElement('label'); label.textContent = title;
      const input = document.createElement(key === 'status' ? 'select' : key === 'notes' ? 'textarea' : 'input');
      input.id = `${question.id}-${key}`; input.name = `${question.id}:${key}`; input.autocomplete = 'off';
      if (key === 'status') for (const status of STATUSES) { const option = document.createElement('option'); option.value = status; option.textContent = status.replaceAll('_', ' '); input.append(option); }
      else if (key.endsWith('Date')) { input.type = 'date'; input.min = '1900-01-01'; input.max = key === 'evidenceDate' ? context.asOf : '9999-12-31'; }
      else input.maxLength = key === 'notes' ? 4000 : 128;
      if (key === 'evidenceRef') input.pattern = '[A-Za-z0-9][A-Za-z0-9._:-]{0,127}';
      if (key === 'notes') { input.rows = 3; label.className = 'wide'; }
      input.value = answer[key];
      const printed = document.createElement('p'); printed.className = 'print-value'; printed.textContent = answer[key] || '________________';
      input.addEventListener('input', () => {
        answer[key] = input.value; printed.textContent = input.value || '________________';
        input.setAttribute('aria-invalid', String(!input.validity.valid)); dirty = true; summarize();
      });
      label.append(input, printed); grid.append(label);
    }
    fragment.append(fieldset);
  }
  $('questions').replaceChildren(fragment); summarize();
}
function download(content, extension, type, kind = 'readiness') {
  const blob = new Blob([content], { type }), url = URL.createObjectURL(blob), link = document.createElement('a');
  // Identifiers have already passed the response contract (no path separators).
  link.href = url; link.download = `${kind}-${selected.id}-${context.assessmentId}-${context.asOf}.${extension}`;
  document.body.append(link); link.click(); link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function setImporting(value) {
  importing = value; $('workspace').setAttribute('aria-busy', String(value));
  for (const input of $('workspace').querySelectorAll('input,textarea,select,button')) input.disabled = value;
}
$('context').addEventListener('submit', (event) => {
  event.preventDefault();
  try {
    context = Object.fromEntries(new FormData(event.currentTarget)); draft = createDraft(catalog, selected.id, context);
    for (const input of event.currentTarget.querySelectorAll('input,textarea,button')) input.disabled = true;
    $('workspace').hidden = false; dirty = true; renderQuestions();
  } catch (cause) { error(cause.message, true); }
});
$('export-json').addEventListener('click', () => {
  try { fieldsValid(); analyze(catalog, selected.id, context, draft); download(JSON.stringify(draft, null, 2) + '\n', 'json', 'application/json'); dirty = false; }
  catch (cause) { error(cause.message, true); }
});
$('export-md').addEventListener('click', () => {
  try { fieldsValid(); download(markdown(catalog, selected.id, context, draft), 'md', 'text/markdown'); }
  catch (cause) { error(cause.message, true); }
});
$('export-workpaper').addEventListener('click', () => {
  try { fieldsValid(); download(workpaper(catalog, selected.id, context, draft), 'md', 'text/markdown', 'preaudit-workpaper'); }
  catch (cause) { error(cause.message, true); }
});
$('question-view').addEventListener('change', summarize);
$('import').addEventListener('change', async (event) => {
  const file = event.target.files[0]; if (!file) return;
  await importExclusively(async () => {
    setImporting(true);
    try {
      if (file.size > MAX_BYTES) throw new Error('Response exceeds the 1 MiB limit');
      let bytes;
      try { bytes = await file.arrayBuffer(); } catch { throw new Error('Unable to read draft file; current answers are unchanged.'); }
      const incoming = importDraft(catalog, selected.id, context, new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes));
      if (dirty && hasAnswerEdits(draft) && !window.confirm('Replace this tab’s unsaved answers with the matching imported draft?')) return;
      draft = incoming; dirty = true; renderQuestions();
    } catch (cause) { error(cause.message, true); }
    finally { event.target.value = ''; setImporting(false); }
  });
});
$('print').addEventListener('click', () => {
  try { fieldsValid(); analyze(catalog, selected.id, context, draft); window.print(); }
  catch (cause) { error(cause.message, true); }
});
window.addEventListener('beforeprint', () => { for (const item of $('questions').children) item.hidden = false; });
window.addEventListener('afterprint', applyView);
window.addEventListener('beforeunload', (event) => { if (dirty || importing) { event.preventDefault(); event.returnValue = ''; } });
try {
  const response = await fetch('/app/readiness/assets/catalog.json', { credentials: 'same-origin', cache: 'no-store' });
  if (!response.ok) throw new Error('Unable to load the readiness catalog; check your session');
  catalog = await response.json();
  const id = window.location.pathname.replace(/\/$/, '').split('/').at(-1);
  for (const item of catalog.frameworks) {
    const link = document.createElement('a'); link.href = `/app/readiness/${item.id}`; link.textContent = item.title;
    if (item.id === id) link.setAttribute('aria-current', 'page'); $('frameworks').append(link);
  }
  if (id !== 'readiness') {
    selected = framework(catalog, id); $('selected-title').textContent = selected.title;
    $('edition').textContent = `Edition: ${selected.edition} · Catalog ${catalog.version}`; $('scope-note').textContent = selected.scopeNote;
    $('context').hidden = false;
    const title = document.createElement('h2'); title.textContent = 'Authoritative references'; $('references').append(title);
    for (const url of selected.sources) { const paragraph = document.createElement('p'), link = document.createElement('a'); link.href = url; link.textContent = url; link.rel = 'noreferrer noopener'; paragraph.append(link); $('references').append(paragraph); }
  }
} catch (cause) { error(cause.message, true); }
