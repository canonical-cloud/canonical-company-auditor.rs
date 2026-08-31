#!/usr/bin/env node
// Opt-in JavaScript/TypeScript runtime exposure probe. Inspected values are never emitted.

import { createHash } from 'node:crypto';

const PROBE_VERSION = '1.0.0';
const SCHEMA_VERSION = 'canonical.runtime-probe/v1';
const SENSITIVE_NAME = /(?:api[_-]?key|auth|bearer|credential|passwd|password|private[_-]?key|secret|session|token)/i;
const SECRET_VALUE_PATTERNS = [
  /AKIA[0-9A-Z]{16}/,
  /gh[pousr]_[A-Za-z0-9_]{20,}/,
  /sk-[A-Za-z0-9_-]{20,}/,
  /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
];

function digest(value) {
  return `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`;
}

function looksSecret(value) {
  return value.length <= 16384 && SECRET_VALUE_PATTERNS.some((pattern) => pattern.test(value));
}

function valueType(value) {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'array';
  return typeof value;
}

export function inspectBindings(target, bindings, maximum = 5000) {
  if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > 10000) {
    throw new TypeError('maximum must be an integer between 1 and 10000');
  }
  const rootDescriptors = Object.getOwnPropertyDescriptors(bindings);
  const queue = Object.entries(rootDescriptors)
    .filter(([name, descriptor]) => !name.startsWith('__') && Object.hasOwn(descriptor, 'value'))
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([name, descriptor]) => ({ location: `module.${name}`, value: descriptor.value, depth: 0 }));
  const seen = new WeakSet();
  const fingerprints = [];
  let scanned = 0;
  let truncated = false;

  while (queue.length > 0) {
    if (scanned >= maximum) {
      truncated = true;
      break;
    }
    const current = queue.shift();
    scanned += 1;
    const { location, value, depth } = current;
    if ((typeof value === 'object' && value !== null) || typeof value === 'function') {
      if (seen.has(value)) continue;
      seen.add(value);
    }

    const leafName = location.slice(location.lastIndexOf('.') + 1);
    const nameMatch = SENSITIVE_NAME.test(leafName);
    const valueMatch = typeof value === 'string' && looksSecret(value);
    if (nameMatch || valueMatch) {
      fingerprints.push({
        category: valueMatch ? 'secret_like_value' : 'sensitive_binding_name',
        locationSha256: digest(location),
        valueSha256: valueMatch ? digest(value) : null,
        valueType: valueType(value),
      });
    }

    if (depth >= 4 || value === null || (typeof value !== 'object' && typeof value !== 'function')) {
      continue;
    }
    let descriptors;
    try {
      descriptors = Object.getOwnPropertyDescriptors(value);
    } catch {
      continue;
    }
    const entries = Object.entries(descriptors)
      .filter(([, descriptor]) => Object.hasOwn(descriptor, 'value'))
      .sort(([left], [right]) => left.localeCompare(right))
      .slice(0, 256);
    for (let index = 0; index < entries.length; index += 1) {
      const [, descriptor] = entries[index];
      queue.push({ location: `${location}.property:${index}`, value: descriptor.value, depth: depth + 1 });
    }
  }

  fingerprints.sort((left, right) =>
    `${left.category}:${left.locationSha256}`.localeCompare(`${right.category}:${right.locationSha256}`),
  );
  return {
    schemaVersion: SCHEMA_VERSION,
    runtime: 'typescript',
    probeVersion: PROBE_VERSION,
    target,
    facts: {
      suspected_secret_count: fingerprints.length,
      scanned_binding_count: scanned,
      truncated,
    },
    fingerprints,
    limitations: [
      'Importing the target may execute normal module initialization; run only in an authorized isolated environment.',
      'The probe reads own data descriptors only; it does not invoke exported functions or getters.',
      'Fingerprints are heuristics and require human validation; no inspected value is emitted.',
    ],
  };
}

async function inspectModule(moduleName, maximum) {
  if (moduleName.length === 0 || moduleName.length > 512 || /[\u0000-\u001f]/.test(moduleName)) {
    throw new TypeError('module specifier is invalid');
  }
  const bindings = await import(moduleName);
  return inspectBindings(moduleName, bindings, maximum);
}

function selfTest() {
  const secret = `sk-${'a'.repeat(32)}`;
  const result = inspectBindings('self_test', { safe: 1, apiToken: secret }, 100);
  const encoded = JSON.stringify(result);
  if (result.facts.suspected_secret_count !== 1 || encoded.includes(secret)) {
    throw new Error('self-test failed');
  }
  process.stdout.write(`${JSON.stringify({ ok: true, probeVersion: PROBE_VERSION })}\n`);
}

async function main() {
  if (process.argv.length !== 2) {
    process.stderr.write('runtime-probe: command-line options are not supported; use documented environment keys\n');
    return 2;
  }
  if (process.env.CANONICAL_PROBE_SELF_TEST === '1') {
    selfTest();
    return 0;
  }
  const moduleName = process.env.CANONICAL_PROBE_MODULE;
  if (moduleName === undefined) {
    process.stderr.write('runtime-probe: CANONICAL_PROBE_MODULE is required\n');
    return 2;
  }
  const maximum = Number.parseInt(process.env.CANONICAL_PROBE_MAX_BINDINGS ?? '5000', 10);
  try {
    const result = await inspectModule(moduleName, maximum);
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    return 0;
  } catch (error) {
    const name = error instanceof Error ? error.name : 'UnknownError';
    process.stderr.write(`runtime-probe: probe failed: ${name}\n`);
    return 1;
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  process.exitCode = await main();
}
