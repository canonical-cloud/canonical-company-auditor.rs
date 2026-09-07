import { createDraft, importDraft, analyze, markdown, framework, STATUSES, MAX_BYTES } from './readiness.mjs';
const $ = (id) => document.getElementById(id);
const fieldLabels = { status: 'Customer declaration', owner: 'Control or remediation owner', notes: 'Explanation / gap / N/A rationale', evidenceRef: 'Opaque evidence reference (no URLs)', evidenceDate: 'Evidence collection date', reviewer: 'Reviewer name (self-reported, not a verified approval)', dueDate: 'Remediation due date' };
let catalog, selected, context, draft, dirty = false;
function error(message) { $('error').textContent = message; if (message) $('error').focus(); }
function summarize() {
  try {
    const report = analyze(catalog, selected.id, context, draft), s = report.summary;
    $('summary').textContent = `Answered ${s.answered}/${s.total} · Declared gaps ${s.declaredGaps} · Unknown evidence ${s.unknownEvidence} · Incomplete metadata ${s.incompleteMetadata} · Reviewer pending ${s.reviewPending} · Overdue ${s.overdueActions}. Customer declarations only; no assurance conclusion.`;
    error('');
  } catch (cause) { error(cause.message); }
}
function renderQuestions() {
  const fragment = document.createDocumentFragment();
  for (const question of selected.questions) {
    const answer = draft.answers.find((item) => item.questionId === question.id);
    const fieldset = document.createElement('fieldset'), legend = document.createElement('legend'), evidence = document.createElement('p'), grid = document.createElement('div');
    fieldset.className = 'editor'; legend.textContent = `${question.id} — ${question.prompt}`;
    evidence.className = 'evidence'; evidence.textContent = `Suggested evidence: ${question.evidence} Primary review method: ${question.method}.`;
    grid.className = 'grid'; fieldset.append(legend, evidence, grid);
    for (const [key, title] of Object.entries(fieldLabels)) {
      const label = document.createElement('label'); label.textContent = title;
      const input = document.createElement(key === 'status' ? 'select' : key === 'notes' ? 'textarea' : 'input');
      input.id = `${question.id}-${key}`; input.name = `${question.id}:${key}`; input.autocomplete = 'off';
      if (key === 'status') for (const status of STATUSES) { const option = document.createElement('option'); option.value = status; option.textContent = status.replaceAll('_', ' '); input.append(option); }
      else if (key.endsWith('Date')) input.type = 'date';
      else input.maxLength = key === 'notes' ? 4000 : 128;
      if (key === 'notes') { input.rows = 3; label.className = 'wide'; }
      input.value = answer[key];
      const printed = document.createElement('p'); printed.className = 'print-value'; printed.textContent = answer[key] || '________________';
      input.addEventListener('input', () => { answer[key] = input.value; printed.textContent = input.value || '________________'; dirty = true; summarize(); });
      label.append(input, printed); grid.append(label);
    }
    fragment.append(fieldset);
  }
  $('questions').replaceChildren(fragment); summarize();
}
function download(content, extension, type) {
  const blob = new Blob([content], { type }), url = URL.createObjectURL(blob), link = document.createElement('a');
  link.href = url; link.download = `readiness-${selected.id}.${extension}`; document.body.append(link); link.click(); link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
$('context').addEventListener('submit', (event) => {
  event.preventDefault();
  try {
    context = Object.fromEntries(new FormData(event.currentTarget)); draft = createDraft(catalog, selected.id, context);
    for (const input of event.currentTarget.querySelectorAll('input,textarea,button')) input.disabled = true;
    $('workspace').hidden = false; dirty = true; renderQuestions();
  } catch (cause) { error(cause.message); }
});
$('export-json').addEventListener('click', () => {
  try { analyze(catalog, selected.id, context, draft); download(JSON.stringify(draft, null, 2) + '\n', 'json', 'application/json'); dirty = false; }
  catch (cause) { error(cause.message); }
});
$('export-md').addEventListener('click', () => {
  try { download(markdown(catalog, selected.id, context, draft), 'md', 'text/markdown'); }
  catch (cause) { error(cause.message); }
});
$('import').addEventListener('change', async (event) => {
  const file = event.target.files[0]; if (!file) return;
  try {
    if (file.size > MAX_BYTES) throw new Error('Response exceeds the 1 MiB limit');
    const incoming = importDraft(catalog, selected.id, context, new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(await file.arrayBuffer()));
    if (dirty && draft.answers.some((answer) => answer.status !== 'unanswered' || answer.notes) && !window.confirm('Replace this tab’s unsaved answers with the matching imported draft?')) return;
    draft = incoming; dirty = true; renderQuestions();
  } catch (cause) { error(cause.message); }
  finally { event.target.value = ''; }
});
$('print').addEventListener('click', () => window.print());
window.addEventListener('beforeunload', (event) => { if (dirty) { event.preventDefault(); event.returnValue = ''; } });
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
} catch (cause) { error(cause.message); }
