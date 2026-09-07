import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { inspectBindings, inspectModule, parseLimit } from './runtime-probe.mjs';

const executable = fileURLToPath(new URL('./runtime-probe.mjs', import.meta.url));
async function fixture(t, source) {
  const dir = await mkdtemp(join(tmpdir(), 'canonical-probe-test-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const file = join(dir, 'customer.mjs'); await writeFile(file, source); return file;
}
test('nested names and aliased values retain sensitivity without disclosing names', () => {
  const shared = { safe: 1 };
  const result = inspectBindings('test', { config: { password: 'ordinary' }, shared, token: shared });
  assert.equal(result.facts.suspected_secret_count, 2);
  assert.equal(result.facts.truncated, false);
  assert.doesNotMatch(JSON.stringify(result.fingerprints), /ordinary|password/);
});
test('accessors are not executed and coverage is incomplete', () => {
  let calls = 0;
  const result = inspectBindings('test', { get token() { calls++; return 'secret'; } });
  assert.equal(calls, 0); assert.equal(result.facts.truncated, true);
});
test('depth, breadth, symbols and long strings do not report complete coverage', () => {
  for (const value of [{ a: { b: { c: { d: { e: {} } } } } }, Object.fromEntries(Array.from({ length: 300 }, (_, i) => [i, i])), { [Symbol('x')]: 1 }, { x: 'a'.repeat(17000) }]) {
    assert.equal(inspectBindings('test', value).facts.truncated, true);
  }
});
test('budget and cyclic inputs stay bounded', () => {
  const cycle = {}; cycle.self = cycle;
  const result = inspectBindings('test', { cycle, a: 1, b: 2 }, 2);
  assert.equal(result.facts.scanned_binding_count, 2); assert.equal(result.facts.truncated, true);
});
test('strict integer parsing rejects trailing text, whitespace, decimals and overflow', () => {
  for (const value of ['1x', ' 1', '1 ', '1.5', '0', '-1', 'Infinity', '10001', '9007199254740993']) assert.throws(() => parseLimit(value, 10000));
  assert.equal(parseLimit('100', 10000), 100);
});
test('property paths cannot alias dotted names', () => {
  const result = inspectBindings('test', { 'a.token': 1, a: { token: 2 } });
  assert.equal(new Set(result.fingerprints.map((x) => x.locationSha256)).size, 2);
});
test('descriptor exceptions are incomplete, not clean', () => {
  const value = new Proxy({}, { ownKeys() { throw new Error('private'); } });
  assert.equal(inspectBindings('test', value).facts.truncated, true);
});
test('module console output never contaminates the CLI result', async (t) => {
  const file = await fixture(t, 'import { writeSync } from "node:fs"; console.log("PRIVATE_CANARY"); console.error("PRIVATE_CANARY"); writeSync(1, "PRIVATE_CANARY"); writeSync(2, "PRIVATE_CANARY"); export const safe = 1;');
  const child = spawnSync(process.execPath, [executable], { env: { ...process.env, CANONICAL_PROBE_SELF_TEST: '', CANONICAL_PROBE_MODULE: file, CANONICAL_PROBE_ALLOW_IMPORT: '1' }, encoding: 'utf8', timeout: 8000 });
  assert.equal(child.status, 0, child.stderr); assert.doesNotMatch(child.stdout + child.stderr, /PRIVATE_CANARY/);
  assert.match(JSON.parse(child.stdout).target, /^sha256:/);
});
test('hung imports terminate on the deadline', async (t) => {
  const file = await fixture(t, 'while (true) {}');
  await assert.rejects(inspectModule(file, 100, 300), /deadline/);
});
test('oversized module output is bounded and not emitted', async (t) => {
  const file = await fixture(t, 'console.log("x".repeat(100000)); setInterval(() => {}, 1000); await new Promise(() => {});');
  await assert.rejects(inspectModule(file, 100, 2000), /output limit/);
});
test('subprocess results cannot inject raw customer values', async (t) => {
  const file = await fixture(t, 'import { writeFileSync } from "node:fs"; writeFileSync(3, JSON.stringify({facts:{scanned_binding_count:1,truncated:false,suspected_secret_count:1},fingerprints:[{category:"PRIVATE_CANARY"}]})); process.exit(0);');
  await assert.rejects(inspectModule(file, 100, 2000), /invalid observation/);
});
test('CLI requires explicit import authorization and redacts all errors', async (t) => {
  const file = await fixture(t, 'const e = new Error("PRIVATE_CANARY"); e.name="PRIVATE_CANARY"; throw e;');
  for (const allow of ['', '1']) {
    const child = spawnSync(process.execPath, [executable], { env: { ...process.env, CANONICAL_PROBE_SELF_TEST: '', CANONICAL_PROBE_MODULE: file, CANONICAL_PROBE_ALLOW_IMPORT: allow }, encoding: 'utf8', timeout: 8000 });
    assert.equal(child.status, 1); assert.equal(child.stdout, ''); assert.doesNotMatch(child.stderr, /PRIVATE_CANARY/);
  }
});
test('nonlocal and source-bearing specifiers are refused', async () => {
  for (const path of ['data:text/javascript,export default 1', 'https://example.com/x.mjs', 'some-package', 'file:///tmp/x?secret=abc']) await assert.rejects(inspectModule(path));
});
