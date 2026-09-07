#!/usr/bin/env node
// Read-only heuristics, not a sandbox or a compliance verdict.
import { createHash } from 'node:crypto';
import { isAbsolute, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { spawn } from 'node:child_process';
import { types } from 'node:util';

const VERSION = '1.1.0';
const SENSITIVE = /(?:api[_-]?key|auth|bearer|credential|passwd|password|private[_-]?key|secret|session|token)/i;
const PATTERNS = [/AKIA[0-9A-Z]{16}/, /gh[pousr]_[A-Za-z0-9_]{20,}/, /sk-[A-Za-z0-9_-]{20,}/, /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/, /-----BEGIN [A-Z ]*PRIVATE KEY-----/];
const HASH = /^sha256:[a-f0-9]{64}$/;
const TYPES = new Set(['null', 'array', 'undefined', 'object', 'function', 'boolean', 'number', 'bigint', 'string', 'symbol']);
const hash = (value) => `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`;
const typeOf = (value) => value === null ? 'null' : Array.isArray(value) ? 'array' : typeof value;
const isObject = (value) => value !== null && (typeof value === 'object' || typeof value === 'function');

function report(target, scanned, truncated, fingerprints) {
  fingerprints.sort((a, b) => `${a.category}:${a.locationSha256}`.localeCompare(`${b.category}:${b.locationSha256}`));
  return {
    schemaVersion: 'canonical.runtime-probe/v1', runtime: 'typescript', probeVersion: VERSION, target,
    facts: { suspected_secret_count: fingerprints.length, scanned_binding_count: scanned, truncated }, fingerprints,
    limitations: [
      'Import runs customer code. Use only an explicitly authorized, externally isolated environment; a child process is not a security sandbox.',
      'Getters are not invoked, but Proxy descriptor traps can execute. Accessors, symbols, errors and depth/size limits make coverage incomplete.',
      'No inspected value is emitted by the observation serializer. No findings does not establish absence of secrets or compliance. Fingerprints remain sensitive evidence.',
    ],
  };
}

export function inspectBindings(target, bindings, maximum = 5000) {
  if (typeof target !== 'string' || target.length > 512 || /[\u0000-\u001f]/.test(target)) throw new TypeError('invalid target');
  if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > 10000 || !isObject(bindings)) throw new TypeError('invalid probe input');
  const queue = [], seen = new WeakSet(), fingerprints = [];
  let truncated = false, scanned = 0;
  function enqueue(value, path, depth) {
    let keys;
    try { keys = Reflect.ownKeys(value); } catch { truncated = true; return; }
    if (keys.some((key) => typeof key === 'symbol' && !(key === Symbol.toStringTag && types.isModuleNamespaceObject(value)))) truncated = true;
    keys = keys.filter((key) => typeof key === 'string');
    const limit = Math.min(256, maximum - queue.length);
    if (keys.length > limit) truncated = true;
    for (const name of keys.slice(0, limit).sort()) {
      let descriptor;
      try { descriptor = Object.getOwnPropertyDescriptor(value, name); } catch { truncated = true; continue; }
      if (!descriptor || !Object.hasOwn(descriptor, 'value')) { truncated = true; continue; }
      queue.push({ value: descriptor.value, path: [...path, name], name, depth });
    }
  }
  enqueue(bindings, [], 0);
  for (let cursor = 0; cursor < queue.length; cursor += 1) {
    const { value, path, name, depth } = queue[cursor];
    scanned += 1;
    const longString = typeof value === 'string' && value.length > 16384;
    if (longString) truncated = true;
    const valueMatch = typeof value === 'string' && !longString && PATTERNS.some((pattern) => pattern.test(value));
    if (SENSITIVE.test(name) || valueMatch) fingerprints.push({
      category: valueMatch ? 'secret_like_value' : 'sensitive_binding_name',
      locationSha256: hash(JSON.stringify(path)), valueSha256: valueMatch ? hash(value) : null, valueType: typeOf(value),
    });
    if (!isObject(value) || seen.has(value)) continue;
    seen.add(value);
    if (depth >= 4) { truncated = true; continue; }
    enqueue(value, path, depth + 1);
  }
  return report(target, scanned, truncated, fingerprints);
}

export function parseLimit(value, maximum) {
  if (typeof value !== 'string' || !/^[1-9][0-9]*$/.test(value)) throw new TypeError('invalid limit');
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed > maximum) throw new TypeError('invalid limit');
  return parsed;
}

// Reconstruct subprocess observations from bounded, allowlisted metadata only.
// Imported code can write fd 3 itself; never reflect arbitrary child data.
function safeReport(value, target, maximum) {
  if (!value || !value.facts || !Array.isArray(value.fingerprints) || value.fingerprints.length > maximum) throw new Error('invalid observation');
  const { scanned_binding_count: scanned, truncated, suspected_secret_count: count } = value.facts;
  if (!Number.isSafeInteger(scanned) || scanned < 0 || scanned > maximum || typeof truncated !== 'boolean' || count !== value.fingerprints.length || count > scanned) throw new Error('invalid observation');
  const fingerprints = value.fingerprints.map((entry) => {
    if (!entry || !['secret_like_value', 'sensitive_binding_name'].includes(entry.category) || !(typeof entry.locationSha256 === 'string' && HASH.test(entry.locationSha256)) || !(entry.valueSha256 === null || (typeof entry.valueSha256 === 'string' && HASH.test(entry.valueSha256))) || !TYPES.has(entry.valueType)) throw new Error('invalid fingerprint');
    return { category: entry.category, locationSha256: entry.locationSha256, valueSha256: entry.valueSha256, valueType: entry.valueType };
  });
  return report(target, scanned, truncated, fingerprints);
}

export async function inspectModule(specifier, maximum = 5000, timeout = 5000) {
  parseLimit(String(maximum), 10000); parseLimit(String(timeout), 30000);
  if (typeof specifier !== 'string' || !specifier || specifier.length > 4096 || /[\u0000-\u001f]/.test(specifier)) throw new TypeError('invalid module');
  let url;
  if (specifier.startsWith('file:')) {
    url = new URL(specifier);
    if (url.search || url.hash || url.username || url.password) throw new TypeError('invalid module');
    fileURLToPath(url);
  } else {
    if (!isAbsolute(specifier) && !specifier.startsWith('./') && !specifier.startsWith('../')) throw new TypeError('local file required');
    url = pathToFileURL(resolve(specifier));
  }
  const target = hash(url.href);
  return new Promise((resolveResult, reject) => {
    const child = spawn(process.execPath, ['--max-old-space-size=128', fileURLToPath(new URL('./runtime-probe-worker.mjs', import.meta.url))], {
      stdio: ['ignore', 'pipe', 'pipe', 'pipe'],
      env: { ...process.env, NODE_OPTIONS: '', NODE_PATH: '', CANONICAL_PROBE_CHILD_MODULE: url.href, CANONICAL_PROBE_CHILD_MAXIMUM: String(maximum), CANONICAL_PROBE_CHILD_TARGET: target },
    });
    let settled = false, outputBytes = 0, resultBytes = 0;
    const chunks = [];
    const timer = setTimeout(() => finish(new Error('probe deadline exceeded')), timeout);
    function finish(error, result) {
      if (settled) return;
      settled = true; clearTimeout(timer); child.kill('SIGKILL');
      for (const stream of child.stdio) stream?.destroy();
      if (error) reject(error); else resolveResult(result);
    }
    for (const stream of [child.stdout, child.stderr]) stream.on('data', (chunk) => {
      outputBytes += chunk.length;
      if (outputBytes > 65536) finish(new Error('probe output limit exceeded'));
    });
    child.stdio[3].on('data', (chunk) => {
      resultBytes += chunk.length;
      if (resultBytes > 4194304) finish(new Error('probe result limit exceeded'));
      else chunks.push(chunk);
    });
    child.on('error', () => finish(new Error('probe process failed')));
    child.on('close', (code) => {
      if (settled) return;
      if (code !== 0) { finish(new Error('probe produced no observation')); return; }
      try { finish(null, safeReport(JSON.parse(Buffer.concat(chunks).toString('utf8')), target, maximum)); }
      catch { finish(new Error('invalid observation')); }
    });
  });
}

async function main() {
  if (process.argv.length !== 2) { process.stderr.write('runtime-probe: arguments are not supported; use documented environment keys\n'); return 2; }
  if (process.env.CANONICAL_PROBE_SELF_TEST === '1') {
    const value = `sk-${'a'.repeat(32)}`;
    const result = inspectBindings('self_test', { config: { token: value } }, 100);
    if (result.facts.suspected_secret_count !== 1 || JSON.stringify(result).includes(value)) return 1;
    process.stdout.write(`${JSON.stringify({ ok: true, probeVersion: VERSION })}\n`); return 0;
  }
  try {
    if (process.env.CANONICAL_PROBE_ALLOW_IMPORT !== '1') throw new Error('authorization required');
    const maximum = parseLimit(process.env.CANONICAL_PROBE_MAX_BINDINGS ?? '5000', 10000);
    const timeout = parseLimit(process.env.CANONICAL_PROBE_TIMEOUT_MS ?? '5000', 30000);
    const result = await inspectModule(process.env.CANONICAL_PROBE_MODULE, maximum, timeout);
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    return result.facts.truncated ? 3 : 0;
  } catch {
    process.stderr.write('runtime-probe: no observation; check authorization, local module path, limits and isolation\n'); return 1;
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) process.exitCode = await main();
